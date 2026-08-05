package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// eventBus fans scan progress out to connected SSE clients.
//
// Publishing never blocks: a subscriber that cannot keep up drops messages
// rather than stalling the scan. Progress is advisory — the frontend always
// reconciles against /api/state — so dropping an intermediate update is
// strictly better than slowing the scanner down.
type eventBus struct {
	mu   sync.RWMutex
	subs map[int]chan sseMessage
	next int
}

type sseMessage struct {
	event string
	data  []byte
}

func newEventBus() *eventBus {
	return &eventBus{subs: make(map[int]chan sseMessage)}
}

func (b *eventBus) subscribe() (int, <-chan sseMessage) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.next
	b.next++
	ch := make(chan sseMessage, 64)
	b.subs[id] = ch
	return id, ch
}

func (b *eventBus) unsubscribe(id int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ch, ok := b.subs[id]; ok {
		delete(b.subs, id)
		close(ch)
	}
}

func (b *eventBus) publish(event string, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	msg := sseMessage{event: event, data: data}

	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subs {
		select {
		case ch <- msg:
		default: // slow consumer: drop rather than block the scan
		}
	}
}

// handleEvents streams scan progress as Server-Sent Events.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	id, ch := s.bus.subscribe()
	defer s.bus.unsubscribe(id)

	// Keepalive comments stop intermediary proxies from timing out an idle
	// stream between scans.
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case msg, open := <-ch:
			if !open {
				return
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", msg.event, msg.data)
			flusher.Flush()
		}
	}
}

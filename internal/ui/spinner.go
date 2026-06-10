package ui

import (
	"fmt"
	"os"
	"sync"
	"time"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Spinner renders an animated status line on stderr. On non-interactive
// terminals it degrades to plain log lines.
type Spinner struct {
	mu   sync.Mutex
	msg  string
	stop chan struct{}
	done chan struct{}
}

func StartSpinner(msg string) *Spinner {
	s := &Spinner{msg: msg, stop: make(chan struct{}), done: make(chan struct{})}
	if !Interactive {
		fmt.Fprintln(os.Stderr, msg)
		return s
	}
	go s.loop()
	return s
}

func (s *Spinner) loop() {
	defer close(s.done)
	t := time.NewTicker(80 * time.Millisecond)
	defer t.Stop()
	i := 0
	for {
		select {
		case <-s.stop:
			fmt.Fprint(os.Stderr, "\r\x1b[2K") // clear the spinner line
			return
		case <-t.C:
			s.mu.Lock()
			msg := s.msg
			s.mu.Unlock()
			fmt.Fprintf(os.Stderr, "\r\x1b[2K%s %s", cAccent.Sprint(spinnerFrames[i%len(spinnerFrames)]), msg)
			i++
		}
	}
}

// Update swaps the message while the spinner keeps animating.
func (s *Spinner) Update(msg string) {
	s.mu.Lock()
	s.msg = msg
	s.mu.Unlock()
}

// Success stops the spinner and prints a green check line.
func (s *Spinner) Success(msg string) { s.finish(cOK.Sprint("✔"), msg) }

// Fail stops the spinner and prints a red cross line.
func (s *Spinner) Fail(msg string) { s.finish(cErr.Sprint("✖"), msg) }

func (s *Spinner) finish(icon, msg string) {
	if Interactive {
		close(s.stop)
		<-s.done
	}
	fmt.Fprintf(os.Stderr, "%s %s\n", icon, msg)
}

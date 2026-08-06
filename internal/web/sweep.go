package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/Emre-Diricanli/ndscan/internal/netinfo"
)

type sweepRequest struct {
	Extra []string `json:"extra"`
}

type sweepResponse struct {
	Started bool     `json:"started"`
	Targets []string `json:"targets"`
	Count   int      `json:"count"`
}

func (s *Server) handleSweep(w http.ResponseWriter, r *http.Request) {
	var req sweepRequest
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req)
	if err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.Extra) > 0 {
		if err := validateTargets(req.Extra); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	locals := netinfo.Locals()
	targets, candidateCount := routedSweepTargets(locals, req.Extra)
	if candidateCount == 0 {
		writeErr(w, http.StatusBadRequest, "no sibling subnets to probe (need an attached IPv4 /24)")
		return
	}
	if err := validateTargets(targets); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.startScan(targets, "quick", true) {
		writeErr(w, http.StatusConflict, "a scan is already running")
		return
	}
	writeJSON(w, http.StatusAccepted, sweepResponse{Started: true, Targets: targets, Count: candidateCount})
}

func routedSweepTargets(locals []netinfo.Network, extra []string) ([]string, int) {
	candidates := netinfo.SiblingCandidates(locals, extra)
	targets := make([]string, 0, len(locals)+len(candidates))
	for _, local := range locals {
		if strings.HasSuffix(local.CIDR, "/32") {
			continue
		}
		targets = append(targets, local.CIDR)
	}
	targets = append(targets, candidates...)
	return targets, len(candidates)
}

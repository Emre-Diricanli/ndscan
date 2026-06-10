package report

import "testing"

func TestCanOpen_DisabledByEnv(t *testing.T) {
	t.Setenv("NDSCAN_NO_OPEN", "1")
	if CanOpen() {
		t.Error("NDSCAN_NO_OPEN should disable opening")
	}
}

func TestOpen_NoOpIsNotError(t *testing.T) {
	t.Setenv("NDSCAN_NO_OPEN", "1")
	// With opening disabled, Open must be a silent no-op (no browser, no error).
	if err := Open("/nonexistent/report.html"); err != nil {
		t.Errorf("Open should be a no-op when disabled, got %v", err)
	}
}

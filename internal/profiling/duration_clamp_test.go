package profiling

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gma1k/podtrace/internal/config"
)

func TestClampProfileDuration(t *testing.T) {
	if got := clampProfileDuration(0); got != config.ProfilingDefaultDuration {
		t.Errorf("clampProfileDuration(0) = %v, want default %v", got, config.ProfilingDefaultDuration)
	}
	if got := clampProfileDuration(-5 * time.Second); got != config.ProfilingDefaultDuration {
		t.Errorf("clampProfileDuration(negative) = %v, want default %v", got, config.ProfilingDefaultDuration)
	}
	over := config.ProfilingMaxDuration + time.Hour
	if got := clampProfileDuration(over); got != config.ProfilingMaxDuration {
		t.Errorf("clampProfileDuration(%v) = %v, want max %v", over, got, config.ProfilingMaxDuration)
	}
	if got := clampProfileDuration(2 * time.Second); got != 2*time.Second {
		t.Errorf("clampProfileDuration(2s) = %v, want 2s unchanged", got)
	}
}

func TestHTTPStart_ClampsRequestedDuration(t *testing.T) {
	h := NewHandler("", nil)
	req := httptest.NewRequest(http.MethodPost, "/profile/start?type=cpu&duration=99h", nil)
	w := httptest.NewRecorder()
	h.HTTPStart(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("HTTPStart status = %d, want %d", w.Code, http.StatusAccepted)
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	got, err := time.ParseDuration(body["duration"])
	if err != nil {
		t.Fatalf("parse echoed duration %q: %v", body["duration"], err)
	}
	if got > config.ProfilingMaxDuration {
		t.Errorf("HTTPStart accepted %v exceeding the %v cap", got, config.ProfilingMaxDuration)
	}
}

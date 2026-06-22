package report

import (
	"strings"
	"testing"
	"time"

	"github.com/podtrace/podtrace/internal/events"
)

type secMock struct{ evs []*events.Event }

func (m *secMock) GetEvents() []*events.Event { return m.evs }
func (m *secMock) FilterEvents(t events.EventType) []*events.Event {
	var out []*events.Event
	for _, e := range m.evs {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}
func (m *secMock) CalculateRate(c int, d time.Duration) float64 { return 0 }
func (m *secMock) StartTime() time.Time                         { return time.Time{} }
func (m *secMock) EndTime() time.Time                           { return time.Time{} }
func (m *secMock) RTTSpikeThreshold() float64                   { return 0 }
func (m *secMock) FSSlowThreshold() float64                     { return 0 }
func (m *secMock) ErrorRateThreshold() float64                  { return 0 }

func TestGenerateSecuritySection(t *testing.T) {
	if s := GenerateSecuritySection(&secMock{}); s != "" {
		t.Errorf("no crypto events should yield empty section, got %q", s)
	}
	m := &secMock{evs: []*events.Event{
		{Type: events.EventAFALG, Target: "aead", Details: "gcm(aes)", Bytes: 1000,
			ProcessName: "python3", K8s: &events.K8sMetadata{PodName: "victim-pod"}},
		{Type: events.EventAFALG, Target: "skcipher", Details: "cbc(aes)", Bytes: 1000,
			ProcessName: "python3", K8s: &events.K8sMetadata{PodName: "victim-pod"}},
		{Type: events.EventAFALG, Target: "aead", Details: "gcm(aes)", Bytes: 0,
			ProcessName: "rootproc", K8s: &events.K8sMetadata{PodName: "root-pod"}},
	}}
	s := GenerateSecuritySection(m)
	if !strings.Contains(s, "CVE-2026-31431") || !strings.Contains(s, "victim-pod") {
		t.Errorf("expected Copy-Fail warning naming the pod, got:\n%s", s)
	}
	if !strings.Contains(s, "Possible privilege-escalation attempt") {
		t.Errorf("expected plain-language headline, got:\n%s", s)
	}
	if !strings.Contains(s, "could gain root on unpatched nodes") {
		t.Errorf("expected plain-language risk line, got:\n%s", s)
	}
	if strings.Contains(s, "skcipher") {
		t.Errorf("informational AF_ALG block should be gone, got:\n%s", s)
	}
	if strings.Contains(s, "root-pod") {
		t.Errorf("root (uid 0) aead must not be flagged, got:\n%s", s)
	}
}

func TestGenerateSecuritySection_OnlyNonSignalsIsEmpty(t *testing.T) {
	m := &secMock{evs: []*events.Event{
		{Type: events.EventAFALG, Target: "skcipher", Bytes: 1000, ProcessName: "p"},
		{Type: events.EventAFALG, Target: "aead", Bytes: 0, ProcessName: "p"},
	}}
	if s := GenerateSecuritySection(m); s != "" {
		t.Errorf("expected empty section when no Copy-Fail signal, got:\n%s", s)
	}
}

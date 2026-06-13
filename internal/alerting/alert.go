package alerting

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/podtrace/podtrace/internal/config"
)

type AlertSeverity string

const (
	SeverityFatal    AlertSeverity = "fatal"
	SeverityCritical AlertSeverity = "critical"
	SeverityWarning  AlertSeverity = "warning"
	SeverityError    AlertSeverity = "error"
)

type Alert struct {
	Severity        AlertSeverity
	Title           string
	Message         string
	Timestamp       time.Time
	Source          string
	PodName         string
	Namespace       string
	Context         map[string]interface{}
	ErrorCode       string
	Recommendations []string
}

func (a *Alert) Key() string {
	if a == nil {
		return ""
	}
	h := sha256.New()
	for _, field := range []string{
		string(a.Severity), a.Source, a.PodName, a.Namespace, a.Title,
	} {
		h.Write([]byte(field))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Clone returns a deep copy. Each delivery goroutine works on its own
// copy because senders mutate the alert (Sanitize truncates fields) while
// siblings are marshaling it.
func (a *Alert) Clone() *Alert {
	if a == nil {
		return nil
	}
	cp := *a
	if a.Context != nil {
		cp.Context = make(map[string]interface{}, len(a.Context))
		for k, v := range a.Context {
			cp.Context[k] = v
		}
	}
	if a.Recommendations != nil {
		cp.Recommendations = append([]string(nil), a.Recommendations...)
	}
	return &cp
}

func (a *Alert) Validate() error {
	if a == nil {
		return fmt.Errorf("alert is nil")
	}
	if a.Severity == "" {
		return fmt.Errorf("alert severity is required")
	}
	if a.Title == "" {
		return fmt.Errorf("alert title is required")
	}
	if a.Message == "" {
		return fmt.Errorf("alert message is required")
	}
	if a.Timestamp.IsZero() {
		return fmt.Errorf("alert timestamp is required")
	}
	if a.Source == "" {
		return fmt.Errorf("alert source is required")
	}
	return nil
}

func (a *Alert) Sanitize() {
	if a == nil {
		return
	}
	a.Title = truncateUTF8(a.Title, 256)
	a.Message = truncateUTF8(a.Message, 1024)
	a.PodName = truncateUTF8(a.PodName, 256)
	a.Namespace = truncateUTF8(a.Namespace, 256)
	a.Source = truncateUTF8(a.Source, 128)
	a.ErrorCode = truncateUTF8(a.ErrorCode, 64)
	if len(a.Recommendations) > 10 {
		a.Recommendations = a.Recommendations[:10]
	}
	for i, rec := range a.Recommendations {
		a.Recommendations[i] = truncateUTF8(rec, 512)
	}
}

// truncateUTF8 caps s to at most max bytes without splitting a multi-byte
// rune.
func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max - 3
	if cut < 0 {
		cut = 0
	}
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

func MapResourceAlertLevel(level uint32) AlertSeverity {
	switch level {
	case 3:
		return SeverityFatal
	case 2:
		return SeverityCritical
	case 1:
		return SeverityWarning
	default:
		return SeverityError
	}
}

func ParseSeverity(severity string) AlertSeverity {
	switch severity {
	case "fatal":
		return SeverityFatal
	case "critical":
		return SeverityCritical
	case "warning":
		return SeverityWarning
	case "error":
		return SeverityError
	default:
		return SeverityError
	}
}

func SeverityLevel(severity AlertSeverity) int {
	switch severity {
	case SeverityFatal:
		return 4
	case SeverityCritical:
		return 3
	case SeverityWarning:
		return 2
	case SeverityError:
		return 1
	default:
		return 0
	}
}

func ShouldSendAlert(severity AlertSeverity) bool {
	if !config.AlertingEnabled {
		return false
	}
	minSeverity := ParseSeverity(config.GetAlertMinSeverity())
	return SeverityLevel(severity) >= SeverityLevel(minSeverity)
}

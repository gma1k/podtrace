package objectstore

import (
	"errors"
	"io"
	"testing"
)

func TestLoggingGCSShouldRetry(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"plain error not retryable", errors.New("permanent failure"), false},
		{"unexpected EOF retryable", io.ErrUnexpectedEOF, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := loggingGCSShouldRetry(tt.err); got != tt.want {
				t.Errorf("loggingGCSShouldRetry(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

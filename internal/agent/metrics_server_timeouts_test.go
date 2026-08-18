package agent

import (
	"net/http"
	"testing"
)

func TestNewMetricsServer_SetsAllTimeouts(t *testing.T) {
	srv := newMetricsServer(http.NewServeMux())

	if srv.ReadHeaderTimeout == 0 {
		t.Error("ReadHeaderTimeout must be set")
	}
	if srv.ReadTimeout == 0 {
		t.Error("ReadTimeout must be set so a slow-body client cannot hold a connection open")
	}
	if srv.WriteTimeout == 0 {
		t.Error("WriteTimeout must be set")
	}
	if srv.IdleTimeout == 0 {
		t.Error("IdleTimeout must be set so idle keep-alive connections are reaped")
	}
}

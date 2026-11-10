package agent

import "testing"

func TestProbeServer_HTTPServerReapsIdleConnections(t *testing.T) {
	srv := NewProbeServer(":0", 0).httpServer()
	if srv.IdleTimeout == 0 {
		t.Error("IdleTimeout must be set so idle keep-alive connections are reaped")
	}
	if srv.ReadTimeout == 0 {
		t.Error("ReadTimeout must be set")
	}
	if srv.ReadHeaderTimeout == 0 {
		t.Error("ReadHeaderTimeout must be set")
	}
	if srv.WriteTimeout == 0 {
		t.Error("WriteTimeout must be set")
	}
	if srv.Addr != ":0" {
		t.Errorf("Addr = %q, want :0", srv.Addr)
	}
}

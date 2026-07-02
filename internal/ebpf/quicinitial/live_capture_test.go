package quicinitial

import (
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestExtractLiveQuicGoInitial captures a real quic-go client Initial through
// a local UDP listener and runs Extract on it.
func TestExtractLiveQuicGoInitial(t *testing.T) {
	bin := os.Getenv("PODTRACE_TEST_H3DEMO_BIN")
	if bin == "" {
		t.Skip("PODTRACE_TEST_H3DEMO_BIN not set")
	}
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	addr := l.LocalAddr().String()

	cmd := exec.Command(bin, "client", "https://"+addr)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()

	var pkts [][]byte
	var info Info
	for len(pkts) < 3 {
		_ = l.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 2000)
		n, _, rerr := l.ReadFromUDP(buf)
		if rerr != nil {
			t.Fatalf("read %d: %v", len(pkts), rerr)
		}
		pkts = append(pkts, buf[:n])
		var xerr error
		info, xerr = ExtractPackets(pkts)
		t.Logf("after %d packet(s): info=%+v err=%v", len(pkts), info, xerr)
		if xerr == nil {
			break
		}
	}
	if info.SNI != "h3demo.local" {
		t.Errorf("SNI = %q, want h3demo.local", info.SNI)
	}
	if len(info.ALPN) == 0 || info.ALPN[0] != "h3" {
		t.Errorf("ALPN = %v, want [h3]", info.ALPN)
	}
}

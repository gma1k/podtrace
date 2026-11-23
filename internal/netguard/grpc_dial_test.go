package netguard

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type connectRecord struct {
	target        string
	authorization string
}

func startConnectProxy(t *testing.T, status int, early string) (string, <-chan connectRecord) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	records := make(chan connectRecord, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		records <- connectRecord{target: req.Host, authorization: req.Header.Get("Proxy-Authorization")}
		if status != http.StatusOK {
			_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"+early)
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err == nil {
			_, _ = conn.Write(buf)
		}
	}()
	return ln.Addr().String(), records
}

func startEchoListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.Copy(conn, conn)
	}()
	return ln.Addr().String()
}

func TestDialGRPCConnectsDirectlyWithoutAProxy(t *testing.T) {
	clearProxyEnv(t)
	withProxy(t, "", nil)
	addr := startEchoListener(t)

	conn, err := DialGRPC(context.Background(), addr)
	if err != nil {
		t.Fatalf("direct dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
}

func TestDialGRPCRefusesTheMetadataAddress(t *testing.T) {
	clearProxyEnv(t)
	withProxy(t, "", nil)
	if _, err := DialGRPC(context.Background(), "169.254.169.254:4317"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("metadata dial got %v, want ErrBlocked", err)
	}
}

func TestDialGRPCRefusesPrivateTargetsWhenBlockingIsOn(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("PODTRACE_EXPORTER_BLOCK_PRIVATE", "true")
	withProxy(t, "", nil)
	if _, err := DialGRPC(context.Background(), "10.255.255.1:4317"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("private dial got %v, want ErrBlocked", err)
	}
}

func TestDialGRPCRejectsAnAddressWithoutAPort(t *testing.T) {
	clearProxyEnv(t)
	if _, err := DialGRPC(context.Background(), "collector"); err == nil {
		t.Fatal("an address without a port was accepted")
	}
}

func TestDialGRPCReturnsAProxyLookupError(t *testing.T) {
	clearProxyEnv(t)
	orig := proxyFromEnvironment
	t.Cleanup(func() { proxyFromEnvironment = orig })
	proxyFromEnvironment = func(*http.Request) (*url.URL, error) { return nil, errors.New("bad proxy configuration") }
	if _, err := DialGRPC(context.Background(), "collector.example.com:4317"); err == nil || !strings.Contains(err.Error(), "bad proxy configuration") {
		t.Fatalf("got %v, want the proxy lookup error", err)
	}
}

func TestDialGRPCTunnelsThroughTheEgressProxy(t *testing.T) {
	clearProxyEnv(t)
	proxyAddr, records := startConnectProxy(t, http.StatusOK, "")
	withProxy(t, "http://user:secret@"+proxyAddr, map[string]string{"collector.example.com": "203.0.113.7"})

	conn, err := DialGRPC(context.Background(), "collector.example.com:4317")
	if err != nil {
		t.Fatalf("proxied dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	rec := <-records
	if rec.target != "collector.example.com:4317" {
		t.Errorf("CONNECT target = %q", rec.target)
	}
	if rec.authorization != "Basic dXNlcjpzZWNyZXQ=" {
		t.Errorf("Proxy-Authorization = %q", rec.authorization)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("tunnel echo = %q, %v", buf, err)
	}
}

func TestDialGRPCKeepsBytesTheProxySentAfterItsReply(t *testing.T) {
	clearProxyEnv(t)
	proxyAddr, records := startConnectProxy(t, http.StatusOK, "EARLY")
	withProxy(t, "http://"+proxyAddr, map[string]string{"collector.example.com": "203.0.113.7"})

	conn, err := DialGRPC(context.Background(), "collector.example.com:4317")
	if err != nil {
		t.Fatalf("proxied dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if rec := <-records; rec.authorization != "" {
		t.Errorf("Proxy-Authorization sent without proxy credentials: %q", rec.authorization)
	}
	if _, ok := conn.(*bufferedConn); !ok {
		t.Fatalf("conn is %T, want the buffered wrapper", conn)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "EARLY" {
		t.Fatalf("early bytes = %q, %v", buf, err)
	}
}

func TestDialGRPCReportsAProxyRefusal(t *testing.T) {
	clearProxyEnv(t)
	proxyAddr, _ := startConnectProxy(t, http.StatusForbidden, "")
	withProxy(t, "http://"+proxyAddr, map[string]string{"collector.example.com": "203.0.113.7"})

	_, err := DialGRPC(context.Background(), "collector.example.com:4317")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("got %v, want the proxy's 403", err)
	}
}

func TestDialGRPCChecksTheTargetBehindTheProxy(t *testing.T) {
	clearProxyEnv(t)
	lookups := withProxy(t, "http://127.0.0.1:1", map[string]string{"metadata.internal": "169.254.169.254"})

	_, err := DialGRPC(context.Background(), "metadata.internal:80")
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("a proxied target resolving to metadata got %v, want ErrBlocked", err)
	}
	if lookups.Load() == 0 {
		t.Fatal("the proxied target was not resolved locally")
	}
}

func TestDialGRPCChecksADirectDialToTheProxyAddress(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("PODTRACE_EXPORTER_BLOCK_PRIVATE", "true")
	t.Setenv("PODTRACE_EGRESS_HTTPS_PROXY", "http://10.0.0.5:3128")
	t.Setenv("PODTRACE_EGRESS_NO_PROXY", "10.0.0.5")

	_, err := DialGRPC(context.Background(), "10.0.0.5:3128")
	if !errors.Is(err, ErrBlocked) || !strings.Contains(err.Error(), "proxy address") {
		t.Fatalf("a tenant endpoint naming the proxy address got %v, want the private-range refusal", err)
	}
}

func TestDialGRPCRefusesAnUnsupportedProxyScheme(t *testing.T) {
	clearProxyEnv(t)
	withProxy(t, "socks5://127.0.0.1:1080", map[string]string{"collector.example.com": "203.0.113.7"})

	_, err := DialGRPC(context.Background(), "collector.example.com:4317")
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("got %v, want the unsupported-scheme refusal", err)
	}
}

func TestDialGRPCReportsAProxyThatIsDown(t *testing.T) {
	clearProxyEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	withProxy(t, "http://"+addr, map[string]string{"collector.example.com": "203.0.113.7"})

	if _, err := DialGRPC(context.Background(), "collector.example.com:4317"); err == nil {
		t.Fatal("dialing a closed proxy succeeded")
	}
}

func TestDialGRPCFailsTheTLSHandshakeWithAnUntrustedHTTPSProxy(t *testing.T) {
	clearProxyEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		_ = conn.Close()
	}()
	withProxy(t, "https://"+ln.Addr().String(), map[string]string{"collector.example.com": "203.0.113.7"})

	_, err = DialGRPC(context.Background(), "collector.example.com:4317")
	if err == nil || !strings.Contains(err.Error(), "TLS to egress proxy") {
		t.Fatalf("got %v, want the TLS handshake failure", err)
	}
}

func TestConnectTunnelReportsAMalformedProxyReply(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	go func() {
		_, _ = http.ReadRequest(bufio.NewReader(server))
		_, _ = io.WriteString(server, "not http\r\n\r\n")
		_ = server.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	proxyURL, _ := url.Parse("http://proxy:3128")
	if _, err := connectTunnel(ctx, client, proxyURL, "collector:4317"); err == nil {
		t.Fatal("a malformed proxy reply was accepted")
	}
}

type writeFailingConn struct {
	net.Conn
}

func (writeFailingConn) Write([]byte) (int, error)   { return 0, errors.New("write refused") }
func (writeFailingConn) SetDeadline(time.Time) error { return nil }

func TestConnectTunnelReportsAWriteFailure(t *testing.T) {
	proxyURL, _ := url.Parse("http://proxy:3128")
	_, err := connectTunnel(context.Background(), writeFailingConn{}, proxyURL, "collector:4317")
	if err == nil || !strings.Contains(err.Error(), "CONNECT collector:4317") || !strings.Contains(err.Error(), "write refused") {
		t.Fatalf("err = %v, want the CONNECT write failure", err)
	}
}

func TestRecoverBlockedRestoresTheSentinelFromAFlattenedStatus(t *testing.T) {
	flattened := errors.New(`rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: netguard: refusing exporter connection to blocked address \"169.254.169.254:4317\": ` + ErrBlocked.Error() + `"`)
	got := RecoverBlocked(flattened)
	if !errors.Is(got, ErrBlocked) {
		t.Fatalf("RecoverBlocked(%v) does not wrap ErrBlocked", flattened)
	}
	if !strings.Contains(got.Error(), "169.254.169.254") {
		t.Errorf("the original detail was lost: %v", got)
	}
}

func TestRecoverBlockedLeavesOtherErrorsAlone(t *testing.T) {
	if RecoverBlocked(nil) != nil {
		t.Error("nil became an error")
	}
	plain := errors.New("rpc error: code = Unavailable desc = connection refused")
	if got := RecoverBlocked(plain); got != plain {
		t.Errorf("an unrelated error was rewrapped: %v", got)
	}
	already := fmt.Errorf("dial: %w", ErrBlocked)
	if got := RecoverBlocked(already); got != already {
		t.Errorf("an error already carrying ErrBlocked was rewrapped: %v", got)
	}
}

func TestDialGRPCTunnelsThroughAnHTTPSProxy(t *testing.T) {
	clearProxyEnv(t)
	issuer := httptest.NewUnstartedServer(http.NotFoundHandler())
	issuer.StartTLS()
	t.Cleanup(issuer.Close)
	pool := x509.NewCertPool()
	pool.AddCert(issuer.Certificate())
	origRoots := proxyRootCAs
	proxyRootCAs = pool
	t.Cleanup(func() { proxyRootCAs = origRoots })

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: issuer.TLS.Certificates, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	targets := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		targets <- req.Host
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
	}()
	withProxy(t, "https://"+ln.Addr().String(), map[string]string{"collector.example.com": "203.0.113.7"})

	conn, err := DialGRPC(context.Background(), "collector.example.com:4317")
	if err != nil {
		t.Fatalf("dial through an https proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, ok := conn.(*tls.Conn); !ok {
		t.Errorf("conn is %T, want the TLS connection to the proxy", conn)
	}
	if got := <-targets; got != "collector.example.com:4317" {
		t.Errorf("CONNECT target = %q", got)
	}
}

type deadlineFailingConn struct {
	net.Conn
	failOn int
	calls  int
}

func (c *deadlineFailingConn) SetDeadline(t time.Time) error {
	c.calls++
	if c.calls == c.failOn {
		return errors.New("deadline refused")
	}
	return c.Conn.SetDeadline(t)
}

func TestConnectTunnelReportsADeadlineFailure(t *testing.T) {
	proxyURL, _ := url.Parse("http://proxy:3128")
	for failOn := 1; failOn <= 2; failOn++ {
		client, server := net.Pipe()
		go func() {
			_, _ = http.ReadRequest(bufio.NewReader(server))
			_, _ = io.WriteString(server, "HTTP/1.1 200 Connection established\r\n\r\n")
		}()
		conn := &deadlineFailingConn{Conn: client, failOn: failOn}
		if _, err := connectTunnel(context.Background(), conn, proxyURL, "collector:4317"); err == nil || !strings.Contains(err.Error(), "deadline refused") {
			t.Errorf("deadline call %d failing: err = %v", failOn, err)
		}
		_ = client.Close()
		_ = server.Close()
	}
}

func TestAGRPCClientAsksTheProxyToConnectByName(t *testing.T) {
	clearProxyEnv(t)
	proxyAddr, records := startConnectProxy(t, http.StatusOK, "")
	withProxy(t, "http://"+proxyAddr, map[string]string{"collector.observability.svc": "203.0.113.7"})

	conn, err := grpc.NewClient(GRPCTarget("collector.observability.svc:4317"),
		grpc.WithContextDialer(DialGRPC),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	conn.Connect()

	select {
	case rec := <-records:
		if rec.target != "collector.observability.svc:4317" {
			t.Errorf("proxy was asked to CONNECT %q, want the hostname so NO_PROXY and proxy allowlists see it", rec.target)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the gRPC client never reached the proxy")
	}
}

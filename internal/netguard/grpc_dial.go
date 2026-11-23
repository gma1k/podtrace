package netguard

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// grpcProxyHandshakeTimeout bounds the CONNECT exchange with the egress
// proxy when the dial context carries no deadline of its own.
const grpcProxyHandshakeTimeout = 30 * time.Second

// proxyRootCAs verifies an https:// egress proxy; nil means the system
// roots.
var proxyRootCAs *x509.CertPool

// DialGRPC is a grpc.WithContextDialer function for exporter egress over
// gRPC. It applies the same rules as HardenedTransport:
//
//   - the address actually dialed is checked by the SSRF guard;
//   - when an egress proxy applies to the target, the target is checked
//     here (the dialer only sees the proxy) and reached through an HTTP
//     CONNECT tunnel;
//   - a direct dial to the proxy's own address is checked like any target.
//
// gRPC turns its own proxy support off once a custom dialer is set, so the
// CONNECT is done here; without it a configured spec.egress.proxy would be
// silently bypassed on gRPC exporters. The proxy is chosen for an https
// request to addr, which is how gRPC itself resolves it.
func DialGRPC(ctx context.Context, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("netguard: gRPC target %q: %w", addr, err)
	}
	probe := &http.Request{Method: http.MethodConnect, URL: &url.URL{Scheme: "https", Host: addr}, Host: addr}
	proxyURL, err := proxyFromEnvironment(probe.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	if proxyURL == nil {
		if isEgressProxyAddress(addr) {
			if err := checkTarget(ctx, host, "exporter request to the proxy address"); err != nil {
				return nil, err
			}
		}
		return dialGuarded(ctx, "tcp", addr)
	}
	if err := checkTarget(ctx, host, "proxied exporter request"); err != nil {
		return nil, err
	}
	return dialThroughProxy(ctx, proxyURL, addr)
}

// dialThroughProxy opens a CONNECT tunnel to addr through proxyURL.
func dialThroughProxy(ctx context.Context, proxyURL *url.URL, addr string) (net.Conn, error) {
	if proxyURL.Scheme != "http" && proxyURL.Scheme != "https" {
		return nil, fmt.Errorf("netguard: egress proxy scheme %q is not supported for gRPC exporters (use http or https)", proxyURL.Scheme)
	}
	proxyAddr := proxyDialAddress(proxyURL.String())
	conn, err := dialGuarded(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	if proxyURL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: proxyURL.Hostname(), RootCAs: proxyRootCAs, MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("netguard: TLS to egress proxy %s: %w", proxyAddr, err)
		}
		conn = tlsConn
	}
	tunnel, err := connectTunnel(ctx, conn, proxyURL, addr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tunnel, nil
}

// connectTunnel sends CONNECT addr over conn and returns the tunnelled
// connection once the proxy answers 2xx.
func connectTunnel(ctx context.Context, conn net.Conn, proxyURL *url.URL, addr string) (net.Conn, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(grpcProxyHandshakeTimeout)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: http.Header{},
	}
	if u := proxyURL.User; u != nil {
		password, _ := u.Password()
		credentials := base64.StdEncoding.EncodeToString([]byte(u.Username() + ":" + password))
		req.Header.Set("Proxy-Authorization", "Basic "+credentials)
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("netguard: CONNECT %s via egress proxy: %w", addr, err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, fmt.Errorf("netguard: CONNECT %s via egress proxy: %w", addr, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("netguard: egress proxy refused CONNECT %s: %s", addr, resp.Status)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	if reader.Buffered() > 0 {
		return &bufferedConn{Conn: conn, reader: reader}, nil
	}
	return conn, nil
}

// bufferedConn returns bytes the proxy sent right after its CONNECT reply
// before reading from the connection again.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// RecoverBlocked restores ErrBlocked on an error from a gRPC call. gRPC
// reports a failed dial as a status carrying only the dial error's text, so
// errors.Is no longer finds the guard's refusal and callers would retry an
// export the guard will refuse every time. The match is on this package's
// own sentinel text, which no remote peer controls on the dial path.
func RecoverBlocked(err error) error {
	if err == nil || errors.Is(err, ErrBlocked) || !strings.Contains(err.Error(), ErrBlocked.Error()) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrBlocked, err)
}

// GRPCTarget is the gRPC client target for an exporter endpoint host:port.
// It selects the passthrough resolver so DialGRPC receives the hostname,
// not an address gRPC resolved beforehand. The egress proxy is then chosen,
// matched against NO_PROXY and asked to CONNECT by name, exactly as for
// OTLP/HTTP: with gRPC's default dns resolver an in-cluster collector named
// in NO_PROXY would still be proxied, and the proxy would only ever see a
// bare IP. The dial guard still checks the address the name resolves to.
func GRPCTarget(hostPort string) string {
	return "passthrough:///" + hostPort
}

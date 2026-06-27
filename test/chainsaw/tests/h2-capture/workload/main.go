package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const traceparent = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"

func handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/err" {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

func startH2C() {
	h2s := &http2.Server{}
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           h2c.NewHandler(http.HandlerFunc(handler), h2s),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { log.Println("h2c server:", srv.ListenAndServe()) }()
}

func startHTTP1() {
	srv := &http.Server{
		Addr:              ":8081",
		Handler:           http.HandlerFunc(handler),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { log.Println("http1 server:", srv.ListenAndServe()) }()
}

func startTLS(cert tls.Certificate) {
	srv := &http.Server{
		Addr:              ":8443",
		Handler:           http.HandlerFunc(handler),
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}},
	}
	go func() { log.Println("tls server:", srv.ListenAndServeTLS("", "")) }()
}

func main() {
	cert, certPool, err := selfSignedCert()
	if err != nil {
		log.Fatal(err)
	}

	startH2C()
	startHTTP1()
	startTLS(cert)
	time.Sleep(2 * time.Second)

	h2cClient := &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return net.Dial(network, addr)
			},
		},
	}

	tlsClient := &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{RootCAs: certPool},
		},
	}

	http1Client := &http.Client{}

	do := func(c *http.Client, method, url string) {
		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			log.Println("req:", err)
			return
		}
		req.Header.Set("traceparent", traceparent)
		resp, err := c.Do(req)
		if err != nil {
			log.Printf("%s %s: %v", method, url, err)
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	methods := []string{"GET", "POST", "PUT", "DELETE"}
	for i := 0; ; i++ {
		if i > 0 && i%20 == 0 {
			h2cClient.CloseIdleConnections()
			tlsClient.CloseIdleConnections()
		}

		do(h2cClient, "GET", "http://127.0.0.1:8080/api/orders")

		m := methods[i%len(methods)]
		do(h2cClient, m, fmt.Sprintf("http://127.0.0.1:8080/h2c/item/%d", i))

		do(tlsClient, "GET", fmt.Sprintf("https://127.0.0.1:8443/secure/order/%d", i))

		do(http1Client, "GET", "http://127.0.0.1:8081/healthz")

		time.Sleep(500 * time.Millisecond)
	}
}

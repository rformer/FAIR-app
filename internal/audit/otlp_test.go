package audit

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"
)

// F-002 T-17 (AC-22): the OTLP client offers TLS 1.2 or later only, whatever
// the server would accept.
func TestOTLPTransportTLSFloor(t *testing.T) {
	var mu sync.Mutex
	var offered []uint16
	conf := &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11, // #nosec G402 -- a server offering old versions
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			offered = append(offered, h.SupportedVersions...)
			mu.Unlock()
			return nil, nil
		}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", conf)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).HandshakeContext(context.Background())
				_ = c.Close()
			}()
		}
	}()
	tr := &OTLPTransport{TLS: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, Timeout: 2 * time.Second} // #nosec G402 -- the handshake fails on the version first
	defer tr.Close()
	err = tr.Send(context.Background(), ln.Addr().(*net.TCPAddr).String(), []ForwardRecord{{Seq: 1, Body: []byte(`{"type":"x"}`)}})
	if err == nil {
		t.Fatal("exported to a TLS 1.1 server")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(offered) == 0 {
		t.Fatal("no ClientHello reached the server")
	}
	for _, v := range offered {
		if v < tls.VersionTLS12 {
			t.Fatalf("the client offered %#x (all: %#v)", v, offered)
		}
	}
}

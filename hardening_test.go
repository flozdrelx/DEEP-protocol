// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func startLimitedServer(t *testing.T, configure func(*Server)) Endpoint {
	t.Helper()
	cert, key, pin, err := GenerateIdentity("node.alpha", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{Authority: "node.alpha", TLSConfig: ServerTLSConfig(identity),
		Handler: HandlerFunc(func(context.Context, string, string) (Resource, error) { return resourceBytes([]byte("data")), nil })}
	configure(server)
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server shutdown did not finish")
		}
	})
	return Endpoint{Address: listener.Addr().String(), PinSHA256: pin}
}

func requireRemoteCode(t *testing.T, err error, code string) {
	t.Helper()
	var remote *RemoteError
	if !errors.As(err, &remote) || remote.Code != code {
		t.Fatalf("wanted %s, got %v", code, err)
	}
}

func TestServerResourceLimitBeforeOutput(t *testing.T) {
	endpoint := startLimitedServer(t, func(s *Server) { s.MaxBytes = 3 })
	var out bytes.Buffer
	_, err := clientFor(t, "node.alpha", endpoint).Fetch(context.Background(), "deep://node.alpha/", &out)
	requireRemoteCode(t, err, "TOO_LARGE")
	if out.Len() != 0 {
		t.Fatal("oversized resource delivered bytes")
	}
}

func TestSessionRequestLimitBeforeProvider(t *testing.T) {
	var opens atomic.Int32
	endpoint := startLimitedServer(t, func(s *Server) {
		s.MaxRequestsPerSession = 1
		s.Handler = HandlerFunc(func(context.Context, string, string) (Resource, error) {
			opens.Add(1)
			return resourceBytes([]byte("ok")), nil
		})
	})
	session, err := clientFor(t, "node.alpha", endpoint).Dial(context.Background(), "deep://node.alpha/")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if _, err = session.Fetch(context.Background(), "deep://node.alpha/", io.Discard); err != nil {
		t.Fatal(err)
	}
	_, err = session.Fetch(context.Background(), "deep://node.alpha/", io.Discard)
	requireRemoteCode(t, err, "SESSION_LIMIT")
	if opens.Load() != 1 {
		t.Fatal("request limit did not protect provider")
	}
}

func TestRateLimitPersistsAcrossReconnect(t *testing.T) {
	endpoint := startLimitedServer(t, func(s *Server) { s.RequestsPerMinute = 1 })
	client := clientFor(t, "node.alpha", endpoint)
	if _, err := client.Fetch(context.Background(), "deep://node.alpha/", io.Discard); err != nil {
		t.Fatal(err)
	}
	_, err := client.Fetch(context.Background(), "deep://node.alpha/", io.Discard)
	requireRemoteCode(t, err, "RATE_LIMITED")
}

func TestMissingHELLOAndSessionLifetimeAreBounded(t *testing.T) {
	t.Run("missing HELLO", func(t *testing.T) {
		endpoint := startLimitedServer(t, func(s *Server) { s.IdleTimeout = 50 * time.Millisecond })
		conn := dialRaw(t, endpoint)
		started := time.Now()
		if _, err := ReadFrame(conn); err == nil {
			t.Fatal("idle peer remained connected")
		}
		if time.Since(started) > time.Second {
			t.Fatal("idle limit was not enforced")
		}
	})
	t.Run("session lifetime", func(t *testing.T) {
		endpoint := startLimitedServer(t, func(s *Server) { s.SessionTimeout = 150 * time.Millisecond; s.IdleTimeout = time.Second })
		session, err := clientFor(t, "node.alpha", endpoint).Dial(context.Background(), "deep://node.alpha/")
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		started := time.Now()
		if _, err := ReadFrame(session.connection); err == nil {
			t.Fatal("expired session remained connected")
		}
		if time.Since(started) > time.Second {
			t.Fatal("session limit was not enforced")
		}
	})
}

func TestConnectionCapIncludesUnauthenticatedPeers(t *testing.T) {
	endpoint := startLimitedServer(t, func(s *Server) { s.MaxConnectionsPerPeer = 1; s.HandshakeTimeout = time.Second })
	first, err := net.Dial("tcp", endpoint.Address)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	// A completed TLS handshake confirms the first connection occupied capacity
	// only in other tests; here two accepts in order still share one peer budget.
	second, err := net.Dial("tcp", endpoint.Address)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var b [1]byte
	_, err = second.Read(b[:])
	if err == nil {
		t.Fatal("excess connection stayed open")
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatal("excess peer was not promptly rejected")
	}
}

func TestProviderCannotInjectTerminalError(t *testing.T) {
	endpoint := startLimitedServer(t, func(s *Server) {
		s.Handler = HandlerFunc(func(context.Context, string, string) (Resource, error) {
			return Resource{}, &RemoteError{"BAD_RESOURCE", "bad\x1b[2Jmessage"}
		})
	})
	_, err := clientFor(t, "node.alpha", endpoint).Fetch(context.Background(), "deep://node.alpha/", io.Discard)
	requireRemoteCode(t, err, "INTERNAL_ERROR")
	if strings.Contains(err.Error(), "\x1b") {
		t.Fatal("terminal control escaped validation")
	}
}

func TestClientRejectsMaliciousErrorText(t *testing.T) {
	endpoint := scriptedPeer(t, func(c net.Conn) error {
		if err := receiveRequest(c); err != nil {
			return err
		}
		return send(c, Error, 1, &RemoteError{"ERROR", "bad\x1b[2Jmessage"}, nil)
	})
	_, err := clientFor(t, "node.alpha", endpoint).Fetch(context.Background(), "deep://node.alpha/", io.Discard)
	if err == nil || strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("unsafe error: %v", err)
	}
}

type noDeadlineConn struct{ net.Conn }

func (noDeadlineConn) SetDeadline(time.Time) error { return errors.New("deadlines unavailable") }
func TestServerRejectsTransportWithoutDeadlines(t *testing.T) {
	cert, key, _, err := GenerateIdentity("node.alpha", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	server, err := (Server{TLSConfig: ServerTLSConfig(identity)}).configured()
	if err != nil {
		t.Fatal(err)
	}
	local, remote := net.Pipe()
	defer local.Close()
	done := make(chan struct{})
	go func() {
		server.serveConnection(context.Background(), noDeadlineConn{remote}, newPeerLimiter(1, 1), "peer")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("deadline failure did not close connection")
	}
}

func TestPeerBudgetBoundAndReconnectAccounting(t *testing.T) {
	limiter := newPeerLimiter(1, 1)
	now := time.Now()
	if !limiter.acquire("peer", now) || limiter.acquire("peer", now) {
		t.Fatal("active peer limit failed")
	}
	if !limiter.allowRequest("peer", now) || limiter.allowRequest("peer", now) {
		t.Fatal("request limit failed")
	}
	limiter.release("peer")
	if !limiter.acquire("peer", now) || limiter.allowRequest("peer", now) {
		t.Fatal("reconnect reset request budget")
	}
	limiter.release("peer")
	if !limiter.acquire("peer", now.Add(time.Minute)) || !limiter.allowRequest("peer", now.Add(time.Minute)) {
		t.Fatal("expired budget did not refill")
	}
	for len(limiter.peers) < maxTrackedPeers {
		key := strings.Repeat("x", len(limiter.peers)%10) + time.Unix(int64(len(limiter.peers)), 0).String()
		if !limiter.acquire(key, now) {
			t.Fatal("could not fill peer table")
		}
		limiter.release(key)
	}
	if limiter.acquire("overflow", now) {
		t.Fatal("peer table grew beyond bound")
	}
	if !limiter.acquire("new-after-expiry", now.Add(2*time.Minute)) {
		t.Fatal("expired inactive peers were not reclaimed")
	}
}

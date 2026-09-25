// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func startResourceServer(t *testing.T, authority string, handler Handler) Endpoint {
	t.Helper()
	cert, key, pin, err := GenerateIdentity(authority, time.Hour)
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
	done := make(chan error, 1)
	server := &Server{Authority: authority, TLSConfig: ServerTLSConfig(identity), Handler: handler, Timeout: 5 * time.Second}
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(6 * time.Second):
			t.Error("server did not stop")
		}
	})
	return Endpoint{Address: listener.Addr().String(), PinSHA256: pin}
}

func resourceBytes(body []byte) Resource {
	return Resource{io.NopCloser(bytes.NewReader(body)), "application/octet-stream", int64(len(body))}
}
func clientFor(t *testing.T, authority string, endpoint Endpoint) *Client {
	t.Helper()
	registry := NewRegistry()
	if err := registry.Register(strings.Split(authority, ".")[1], StaticAdapter{authority: endpoint}); err != nil {
		t.Fatal(err)
	}
	return NewClient(registry)
}

func TestStreamingAndSessionReuse(t *testing.T) {
	large := bytes.Repeat([]byte{0, 255, 42, 17}, (3*1024*1024+100)/4)
	resources := map[string][]byte{"/large": large, "/empty": {}, "/small": []byte("same session")}
	endpoint := startResourceServer(t, "node.alpha", HandlerFunc(func(_ context.Context, path, query string) (Resource, error) {
		if query != "" {
			return Resource{}, fmt.Errorf("fragment or query leaked")
		}
		body, ok := resources[path]
		if !ok {
			return Resource{}, &RemoteError{"NOT_FOUND", "missing"}
		}
		return resourceBytes(body), nil
	}))
	client := clientFor(t, "node.alpha", endpoint)
	session, err := client.Dial(context.Background(), "deep://node.alpha/")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if !session.Security.PostQuantumKeyExchange || session.Security.KeyExchange != "X25519MLKEM768" {
		t.Fatalf("missing actual PQC evidence: %+v", session.Security)
	}
	for _, path := range []string{"/large", "/empty", "/small", "/large"} {
		var output bytes.Buffer
		result, err := session.Fetch(context.Background(), "deep://node.alpha"+path+"#client-only", &output)
		if err != nil {
			t.Fatal(err)
		}
		expected := sha256.Sum256(resources[path])
		if !bytes.Equal(output.Bytes(), resources[path]) || result.Size != int64(len(resources[path])) || result.SHA256 != hex.EncodeToString(expected[:]) {
			t.Fatal("stream mismatch")
		}
	}
}

func TestConcurrentNetworksDoNotMix(t *testing.T) {
	registry := NewRegistry()
	for _, network := range []string{"alpha", "beta"} {
		body := []byte(network)
		authority := "node." + network
		endpoint := startResourceServer(t, authority, HandlerFunc(func(context.Context, string, string) (Resource, error) { return resourceBytes(body), nil }))
		if err := registry.Register(network, StaticAdapter{authority: endpoint}); err != nil {
			t.Fatal(err)
		}
	}
	client := NewClient(registry)
	var workers sync.WaitGroup
	failures := make(chan error, 40)
	for index := 0; index < 40; index++ {
		network := []string{"alpha", "beta"}[index%2]
		workers.Add(1)
		go func() {
			defer workers.Done()
			var out bytes.Buffer
			_, err := client.Fetch(context.Background(), "deep://node."+network+"/", &out)
			if err == nil && out.String() != network {
				err = fmt.Errorf("cross-network response: %q", out.String())
			}
			if err != nil {
				failures <- err
			}
		}()
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}

func TestProviderSizeAndClientLimit(t *testing.T) {
	for _, announced := range []int64{2, 6} {
		t.Run(fmt.Sprint(announced), func(t *testing.T) {
			endpoint := startResourceServer(t, "node.alpha", HandlerFunc(func(context.Context, string, string) (Resource, error) {
				r := resourceBytes([]byte("abcd"))
				r.Size = announced
				return r, nil
			}))
			_, err := clientFor(t, "node.alpha", endpoint).Fetch(context.Background(), "deep://node.alpha/", io.Discard)
			var remote *RemoteError
			if !errors.As(err, &remote) || remote.Code != "RESOURCE_CHANGED" {
				t.Fatalf("expected size change rejection: %v", err)
			}
		})
	}
	endpoint := startResourceServer(t, "node.alpha", HandlerFunc(func(context.Context, string, string) (Resource, error) { return resourceBytes([]byte("abcd")), nil }))
	client := clientFor(t, "node.alpha", endpoint)
	client.MaxBytes = 3
	var out bytes.Buffer
	if _, err := client.Fetch(context.Background(), "deep://node.alpha/", &out); err == nil || out.Len() != 0 {
		t.Fatal("did not reject announced resource limit")
	}
}

func TestSessionBusyIsImmediateAndFirstRequestSurvives(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	endpoint := startResourceServer(t, "node.alpha", HandlerFunc(func(ctx context.Context, _, _ string) (Resource, error) {
		close(entered)
		select {
		case <-release:
			return resourceBytes([]byte("ok")), nil
		case <-ctx.Done():
			return Resource{}, ctx.Err()
		}
	}))
	session, err := clientFor(t, "node.alpha", endpoint).Dial(context.Background(), "deep://node.alpha/")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	first := make(chan error, 1)
	go func() { _, err := session.Fetch(context.Background(), "deep://node.alpha/", io.Discard); first <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first request not active")
	}
	started := time.Now()
	_, err = session.Fetch(context.Background(), "deep://node.alpha/", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "busy") || time.Since(started) > time.Second {
		t.Fatalf("busy request blocked: %v", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

func TestCanceledFetchAndServerShutdown(t *testing.T) {
	endpoint := startResourceServer(t, "node.alpha", HandlerFunc(func(ctx context.Context, _, _ string) (Resource, error) {
		reader, writer := io.Pipe()
		context.AfterFunc(ctx, func() { writer.Close() })
		return Resource{reader, "text/plain", 10}, nil
	}))
	client := clientFor(t, "node.alpha", endpoint)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := client.Fetch(ctx, "deep://node.alpha/", io.Discard)
	if err == nil || time.Since(started) > 2*time.Second {
		t.Fatalf("canceled transfer was not bounded: %v", err)
	}
}

type pipeAddress struct{}

func (pipeAddress) Network() string { return "memory" }
func (pipeAddress) String() string  { return "peer-alpha" }

type pipeListener struct {
	incoming chan net.Conn
	closed   chan struct{}
	once     sync.Once
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.incoming:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *pipeListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *pipeListener) Addr() net.Addr { return pipeAddress{} }

func TestCustomTransportCarriesSamePQCProtocol(t *testing.T) {
	cert, key, pin, err := GenerateIdentity("node.weird", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	listener := &pipeListener{incoming: make(chan net.Conn), closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := Server{Authority: "node.weird", TLSConfig: ServerTLSConfig(identity), Handler: HandlerFunc(func(context.Context, string, string) (Resource, error) {
		return resourceBytes([]byte("without TCP")), nil
	})}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	client := clientFor(t, "node.weird", Endpoint{Address: "peer-alpha", PinSHA256: pin, Transport: "memory"})
	client.Dialers["memory"] = func(ctx context.Context, _ Endpoint) (net.Conn, error) {
		local, remote := net.Pipe()
		select {
		case listener.incoming <- remote:
			return local, nil
		case <-ctx.Done():
			local.Close()
			remote.Close()
			return nil, ctx.Err()
		}
	}
	var out bytes.Buffer
	result, err := client.Fetch(context.Background(), "deep://node.weird/", &out)
	cancel()
	if serveErr := <-done; serveErr != nil {
		t.Fatal(serveErr)
	}
	if err != nil || out.String() != "without TCP" || !result.Security.PostQuantumKeyExchange {
		t.Fatalf("custom transport: %+v %v %q", result, err, out.String())
	}
}

// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testProxy(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				handler(c)
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done; workers.Wait() })
	return listener.Addr().String()
}
func TestProxyNativeFramingAndExactConsumption(t *testing.T) {
	var wire bytes.Buffer
	request := ProxyRequest{Version: 1, Operation: "resolve", Authority: "node.alpha"}
	if err := WriteProxyMessage(&wire, request); err != nil {
		t.Fatal(err)
	}
	wire.WriteString("next TLS bytes")
	var got ProxyRequest
	if err := ReadProxyMessage(&wire, &got); err != nil || got != request {
		t.Fatal(got, err)
	}
	if wire.String() != "next TLS bytes" {
		t.Fatal("frame reader consumed following stream")
	}
	for _, raw := range []string{
		"GET / HTTP/1.1\r\nHost: localhost\r\n", "DPRX0001" + string([]byte{0, 0, 0, 0}),
		"DPRX0001" + string([]byte{0, 0, 16, 1}),
	} {
		if ReadProxyMessage(strings.NewReader(raw), &got) == nil {
			t.Fatal("accepted invalid frame")
		}
	}
	for _, raw := range []string{`{"version":1,"version":1,"operation":"resolve","authority":"node.alpha"}`, `{"version":1,"operation":"resolve","authority":null}`, `{"version":1,"operation":"resolve","Authority":"node.alpha"}`} {
		header := []byte("DPRX0001\x00\x00\x00\x00")
		binary.BigEndian.PutUint32(header[8:], uint32(len(raw)))
		if ReadProxyMessage(bytes.NewReader(append(header, raw...)), &got) == nil {
			t.Fatal("accepted ambiguous JSON")
		}
	}
}
func TestProxyConfigurationRequiresExplicitAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	os.WriteFile(path, []byte(`{"version":2}`), 0600)
	registry, err := LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = registry.Resolve(context.Background(), "node.alpha"); err == nil || !strings.Contains(err.Error(), "no adapter installed") {
		t.Fatal(err)
	}
	for _, address := range []string{"example.com:41001", "0.0.0.0:41001", "192.0.2.1:41001", "127.0.0.1:0", "127.0.0.1:041001", "[::]:41001", "[::1%zone]:41001"} {
		if ValidateProxyAddress(address) == nil {
			t.Fatal("accepted", address)
		}
	}
	for _, address := range []string{"127.0.0.1:41001", "[::1]:41001"} {
		if err := ValidateProxyAddress(address); err != nil {
			t.Fatal(err)
		}
	}
}
func TestProxyPreservesTLSAndFetch(t *testing.T) {
	root := t.TempDir()
	want := bytes.Repeat([]byte{0, 255, 1, 2, 3}, 20000)
	os.WriteFile(filepath.Join(root, "payload.bin"), want, 0600)
	files, err := NewFileHandler(root)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	endpoint := startResourceServer(t, "node.alpha", files)
	address := testProxy(t, func(c net.Conn) {
		var r ProxyRequest
		if err := ReadProxyMessage(c, &r); err != nil {
			t.Error(err)
			return
		}
		if r.Authority != "node.alpha" {
			t.Error("wrong authority")
			return
		}
		if r.Operation == "resolve" {
			_ = WriteProxyMessage(c, ProxyResponse{Version: 1, OK: true, PinSHA256: endpoint.PinSHA256})
			return
		}
		if r.Operation != "connect" || r.PinSHA256 != endpoint.PinSHA256 {
			t.Error("pin not bound to connect")
			return
		}
		up, err := net.DialTimeout("tcp", endpoint.Address, time.Second)
		if err != nil {
			t.Error(err)
			return
		}
		defer up.Close()
		if err := WriteProxyMessage(c, ProxyResponse{Version: 1, OK: true, PinSHA256: endpoint.PinSHA256}); err != nil {
			t.Error(err)
			return
		}
		done := make(chan struct{})
		go func() { _, _ = io.Copy(up, c); _ = up.Close(); close(done) }()
		_, _ = io.Copy(c, up)
		_ = c.Close()
		<-done
	})
	registry := NewRegistry()
	if err := registry.SetProxy(address); err != nil {
		t.Fatal(err)
	}
	client := NewClient(registry)
	var got bytes.Buffer
	result, err := client.Fetch(context.Background(), "deep://node.alpha/payload.bin", &got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) || !result.Security.PostQuantumAuthentication || !result.Security.PostQuantumKeyExchange {
		t.Fatal("body/security changed")
	}
}
func TestProxyRejectsChangedPinAndHonorsCancellation(t *testing.T) {
	address := testProxy(t, func(c net.Conn) {
		var r ProxyRequest
		if ReadProxyMessage(c, &r) != nil {
			return
		}
		_ = WriteProxyMessage(c, ProxyResponse{Version: 1, OK: true, PinSHA256: strings.Repeat("b", 64)})
	})
	_, err := DialProxy(context.Background(), Endpoint{Address: proxyEndpointAddress(address, "node.alpha"), PinSHA256: strings.Repeat("a", 64), Transport: ProxyTransport})
	if err == nil || !strings.Contains(err.Error(), "pin changed") {
		t.Fatal(err)
	}
	waiter := testProxy(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := (ProxyAdapter{Address: waiter}).Resolve(ctx, "node.alpha"); err == nil || time.Since(start) > time.Second {
		t.Fatal("cancellation failed", err)
	}
}

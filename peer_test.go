// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func scriptedPeer(t *testing.T, script func(net.Conn) error) Endpoint {
	t.Helper()
	cert, key, pin, err := GenerateIdentity("node.alpha", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", ServerTLSConfig(identity))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(3 * time.Second))
		done <- script(connection)
	}()
	t.Cleanup(func() {
		listener.Close()
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Error("scripted peer did not stop")
		}
	})
	return Endpoint{Address: listener.Addr().String(), PinSHA256: pin}
}

func receiveRequest(connection net.Conn) error {
	if _, err := ReadFrame(connection); err != nil {
		return err
	}
	if err := send(connection, Welcome, 0, welcomeMetadata{1, MaxChunkSize}, nil); err != nil {
		return err
	}
	_, err := ReadFrame(connection)
	return err
}

func TestClientRejectsInvalidStreams(t *testing.T) {
	scripts := map[string]func(net.Conn) error{
		"wrong ID": func(c net.Conn) error { return send(c, Response, 2, responseMetadata{"text/plain", 0}, nil) },
		"wrong hash": func(c net.Conn) error {
			if err := send(c, Response, 1, responseMetadata{"text/plain", 1}, nil); err != nil {
				return err
			}
			if err := send(c, Data, 1, struct{}{}, []byte("x")); err != nil {
				return err
			}
			return send(c, End, 1, endMetadata{1, strings.Repeat("0", 64)}, nil)
		},
		"missing END": func(c net.Conn) error {
			if err := send(c, Response, 1, responseMetadata{"text/plain", 1}, nil); err != nil {
				return err
			}
			return send(c, Data, 1, struct{}{}, []byte("x"))
		},
		"extra bytes": func(c net.Conn) error {
			if err := send(c, Response, 1, responseMetadata{"text/plain", 1}, nil); err != nil {
				return err
			}
			return send(c, Data, 1, struct{}{}, []byte("xx"))
		},
		"oversized declared chunk": func(c net.Conn) error {
			if err := send(c, Response, 1, responseMetadata{"text/plain", 100000}, nil); err != nil {
				return err
			}
			raw := rawFrame(Data, 1, []byte(`{}`), []byte("x"))[:HeaderSize]
			binary.BigEndian.PutUint32(raw[16:20], MaxChunkSize+1)
			return writeAll(c, raw)
		},
		"negative size": func(c net.Conn) error { return send(c, Response, 1, responseMetadata{"text/plain", -1}, nil) },
		"invalid metadata type": func(c net.Conn) error {
			return WriteFrame(c, Frame{Type: Response, RequestID: 1, Metadata: []byte(`{"media_type":"text/plain","size":true}`)})
		},
	}
	for name, script := range scripts {
		t.Run(name, func(t *testing.T) {
			endpoint := scriptedPeer(t, func(c net.Conn) error {
				if err := receiveRequest(c); err != nil {
					return err
				}
				return script(c)
			})
			if _, err := clientFor(t, "node.alpha", endpoint).Fetch(context.Background(), "deep://node.alpha/", io.Discard); err == nil {
				t.Fatal("accepted invalid stream")
			}
		})
	}
}

func dialRaw(t *testing.T, endpoint Endpoint) *tls.Conn {
	t.Helper()
	config, err := ClientTLSConfig("node.alpha", endpoint.PinSHA256)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := tls.Dial("tcp", endpoint.Address, config)
	if err != nil {
		t.Fatal(err)
	}
	connection.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { connection.Close() })
	return connection
}

func TestServerProtocolStateAndVersion(t *testing.T) {
	endpoint := startResourceServer(t, "node.alpha", HandlerFunc(func(context.Context, string, string) (Resource, error) { return resourceBytes([]byte("x")), nil }))
	for _, versions := range [][]int{{2}, {1, 1}, {}} {
		connection := dialRaw(t, endpoint)
		if err := send(connection, Hello, 0, helloMetadata{versions}, nil); err != nil {
			t.Fatal(err)
		}
		frame, err := ReadFrame(connection)
		if err != nil {
			t.Fatal(err)
		}
		if frame.Type != Error || frame.RequestID != 0 {
			t.Fatalf("accepted versions %v", versions)
		}
		connection.Close()
	}
	connection := dialRaw(t, endpoint)
	if err := send(connection, Hello, 0, helloMetadata{[]int{1}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(connection); err != nil {
		t.Fatal(err)
	}
	request := requestMetadata{"node.alpha", "/", "", "FETCH"}
	if err := send(connection, Request, 9, request, nil); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []MessageType{Response, Data, End} {
		frame, err := ReadFrame(connection)
		if err != nil || frame.Type != kind || frame.RequestID != 9 {
			t.Fatalf("transaction: %+v %v", frame, err)
		}
	}
	if err := send(connection, Request, 9, request, nil); err != nil {
		t.Fatal(err)
	}
	frame, err := ReadFrame(connection)
	if err != nil {
		t.Fatal(err)
	}
	var remote RemoteError
	if frame.Type != Error || DecodeMetadata(frame, &remote, "code", "message") != nil || remote.Code != "PROTOCOL_ERROR" {
		t.Fatal("accepted reused request ID")
	}
}

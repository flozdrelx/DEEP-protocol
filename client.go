// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const DefaultMaxBytes int64 = 1 << 30

// DialFunc opens a reliable byte stream. The DEEP core then applies its TLS profile.
// Custom networks can use tunnels or overlay connections without changing messages.
type DialFunc func(context.Context, Endpoint) (net.Conn, error)

type Client struct {
	Registry *Registry
	Dialers  map[string]DialFunc
	Timeout  time.Duration
	MaxBytes int64
	// Identity is optional for public servers and required by private servers.
	// Configure it before sharing the client between goroutines.
	Identity *tls.Certificate
}

func NewClient(registry *Registry) *Client {
	return &Client{Registry: registry, Timeout: 30 * time.Second, MaxBytes: DefaultMaxBytes,
		Dialers: map[string]DialFunc{"tcp": func(ctx context.Context, endpoint Endpoint) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", endpoint.Address)
		}},
	}
}

type Result struct {
	MediaType string       `json:"media_type"`
	Size      int64        `json:"size"`
	SHA256    string       `json:"sha256"`
	Security  SecurityInfo `json:"security"`
}

type Session struct {
	Security   SecurityInfo
	authority  string
	connection net.Conn
	timeout    time.Duration
	maxBytes   int64
	nextID     uint32
	mutex      sync.Mutex
	closed     atomic.Bool
}

func (c *Client) Dial(ctx context.Context, value string) (*Session, error) {
	uri, err := ParseURI(value)
	if err != nil {
		return nil, err
	}
	if c.Registry == nil {
		return nil, errors.New("no network adapter registry")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	endpoint, err := c.Registry.Resolve(ctx, uri.Authority)
	if err != nil {
		return nil, err
	}
	transport := endpoint.Transport
	if transport == "" {
		transport = "tcp"
	}
	dial := c.Dialers[transport]
	if dial == nil {
		return nil, fmt.Errorf("no transport registered for %q", transport)
	}
	config, err := ClientTLSConfig(uri.Authority, endpoint.PinSHA256)
	if err != nil {
		return nil, err
	}
	if c.Identity != nil {
		if err := ValidateClientIdentity(*c.Identity); err != nil {
			return nil, fmt.Errorf("client identity: %w", err)
		}
		config.Certificates = []tls.Certificate{*c.Identity}
	}
	raw, err := dial(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	connection := tls.Client(raw, config)
	success := false
	defer func() {
		if !success {
			raw.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	if err := setDeadline(connection, ctx, timeout); err != nil {
		return nil, err
	}
	if err := connection.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("DEEP TLS handshake: %w", err)
	}
	security, err := InspectSecurity(connection.ConnectionState())
	if err != nil {
		return nil, err
	}
	if err := send(connection, Hello, 0, helloMetadata{[]int{ProtocolVersion}}, nil); err != nil {
		return nil, err
	}
	frame, err := ReadFrame(connection)
	if err != nil {
		return nil, err
	}
	if err := expect(frame, Welcome, 0); err != nil {
		return nil, err
	}
	var welcome welcomeMetadata
	if err := DecodeMetadata(frame, &welcome, "version", "max_chunk"); err != nil {
		return nil, err
	}
	if welcome.Version != ProtocolVersion || welcome.MaxChunk != MaxChunkSize {
		return nil, protocolError("unsupported protocol version or chunk size")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	maxBytes := c.MaxBytes
	if maxBytes == 0 {
		maxBytes = DefaultMaxBytes
	}
	if maxBytes < 0 || maxBytes > MaxResourceSize {
		return nil, errors.New("invalid resource byte limit")
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	success = true
	return &Session{Security: security, authority: uri.Authority, connection: connection,
		timeout: timeout, maxBytes: maxBytes, nextID: 1}, nil
}

func (c *Client) Fetch(ctx context.Context, uri string, destination io.Writer) (Result, error) {
	session, err := c.Dial(ctx, uri)
	if err != nil {
		return Result{}, err
	}
	defer session.Close()
	return session.Fetch(ctx, uri, destination)
}

// Fetch streams bytes to destination. Callers MUST discard partial output on error.
// The session can be reused for successful FETCHes of the same authority.
func (s *Session) Fetch(ctx context.Context, value string, destination io.Writer) (result Result, err error) {
	if destination == nil {
		return result, errors.New("nil resource destination")
	}
	uri, err := ParseURI(value)
	if err != nil {
		return result, err
	}
	if uri.Authority != s.authority {
		return result, errors.New("session belongs to a different authority")
	}
	if !s.mutex.TryLock() {
		return result, errors.New("session is busy; wait for FETCH to finish or open another session")
	}
	defer s.mutex.Unlock()
	if s.closed.Load() {
		return result, net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if s.nextID == 0 {
		return result, errors.New("request IDs exhausted; open a new session")
	}
	defer func() {
		if err != nil {
			s.closed.Store(true)
			s.connection.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { s.connection.Close() })
	defer stop()
	if err = setDeadline(s.connection, ctx, s.timeout); err != nil {
		return result, err
	}
	id := s.nextID
	s.nextID++
	request := requestMetadata{uri.Authority, uri.Path, uri.Query, "FETCH"}
	if err = send(s.connection, Request, id, request, nil); err != nil {
		return result, err
	}
	frame, err := ReadFrame(s.connection)
	if err != nil {
		return result, err
	}
	if err = expect(frame, Response, id); err != nil {
		return result, err
	}
	var metadata responseMetadata
	if err = DecodeMetadata(frame, &metadata, "media_type", "size"); err != nil {
		return result, err
	}
	if !validateMediaType(metadata.MediaType) || metadata.Size < 0 || metadata.Size > MaxResourceSize {
		return result, protocolError("invalid resource metadata")
	}
	if metadata.Size > s.maxBytes {
		return result, fmt.Errorf("resource exceeds client limit of %d bytes", s.maxBytes)
	}
	hash := sha256.New()
	var received int64
	for {
		frame, err = ReadFrame(s.connection)
		if err != nil {
			return result, err
		}
		if frame.RequestID != id {
			return result, protocolError("response request ID mismatch")
		}
		switch frame.Type {
		case Data:
			if err = DecodeMetadata(frame, &struct{}{}); err != nil {
				return result, err
			}
			if int64(len(frame.Body)) > metadata.Size-received {
				return result, protocolError("received more bytes than announced")
			}
			if err = writeAll(destination, frame.Body); err != nil {
				return result, err
			}
			hash.Write(frame.Body)
			received += int64(len(frame.Body))
		case End:
			var ending endMetadata
			if err = DecodeMetadata(frame, &ending, "size", "sha256"); err != nil {
				return result, err
			}
			digest := hex.EncodeToString(hash.Sum(nil))
			if received != metadata.Size || ending.Size != received || ending.SHA256 != digest {
				return result, protocolError("resource size or SHA-256 mismatch")
			}
			if err = ctx.Err(); err != nil {
				return result, err
			}
			if err = s.connection.SetDeadline(time.Time{}); err != nil {
				return result, err
			}
			return Result{metadata.MediaType, received, digest, s.Security}, nil
		case Error:
			return result, expect(frame, End, id)
		default:
			return result, protocolError("expected DATA or END")
		}
	}
}

func (s *Session) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	if s.mutex.TryLock() {
		if s.connection.SetWriteDeadline(time.Now().Add(200*time.Millisecond)) == nil {
			_ = send(s.connection, Close, 0, struct{}{}, nil)
		}
		s.mutex.Unlock()
	}
	return s.connection.Close()
}

func expect(frame Frame, kind MessageType, id uint32) error {
	if frame.RequestID != id {
		return protocolError("response request ID mismatch")
	}
	if frame.Type == Error {
		var remote RemoteError
		if err := DecodeMetadata(frame, &remote, "code", "message"); err != nil {
			return err
		}
		if ValidateRemoteError(&remote) != nil {
			return protocolError("invalid remote error")
		}
		return &remote
	}
	if frame.Type != kind {
		return protocolError("unexpected message type")
	}
	return nil
}

func setDeadline(connection net.Conn, ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if earlier, ok := ctx.Deadline(); ok && earlier.Before(deadline) {
		deadline = earlier
	}
	return connection.SetDeadline(deadline)
}

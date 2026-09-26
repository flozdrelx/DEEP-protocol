// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type Server struct {
	Authority             string
	TLSConfig             *tls.Config
	Handler               Handler
	Timeout               time.Duration
	MaxConnections        int
	MaxConnectionsPerPeer int
	MaxRequestsPerSession uint32
	MaxBytes              int64
	RequestsPerMinute     int
	HandshakeTimeout      time.Duration
	IdleTimeout           time.Duration
	SessionTimeout        time.Duration
}

// Serve accepts raw reliable connections and authenticates the DEEP TLS profile.
// Canceling ctx closes the listener and all its connections before returning.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if err := ValidateAuthority(s.Authority); err != nil {
		return err
	}
	if s.TLSConfig == nil || s.Handler == nil {
		return errors.New("server requires TLS identity and resource handler")
	}
	configured, err := s.configured()
	if err != nil {
		return err
	}
	s = &configured
	if len(s.TLSConfig.Certificates) != 1 {
		return errors.New("server requires exactly one static identity")
	}
	if err := ValidateServerIdentity(s.TLSConfig.Certificates[0], s.Authority); err != nil {
		return err
	}
	s.TLSConfig = s.TLSConfig.Clone()
	peers := newPeerLimiter(s.MaxConnectionsPerPeer, s.RequestsPerMinute)
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); listener.Close(); workers.Wait() }()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	capacity := make(chan struct{}, s.MaxConnections)
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		key := peerKey(connection.RemoteAddr())
		if !peers.acquire(key, time.Now()) {
			connection.Close()
			continue
		}
		select {
		case capacity <- struct{}{}:
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-capacity; peers.release(key) }()
				s.serveConnection(ctx, connection, peers, key)
			}()
		default:
			peers.release(key)
			connection.Close()
		}
	}
}

func (s *Server) serveConnection(ctx context.Context, raw net.Conn, peers *peerLimiter, peer string) {
	ctx, endSession := context.WithTimeout(ctx, s.SessionTimeout)
	defer endSession()
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	connection := tls.Server(raw, s.TLSConfig)
	handshakeCtx, cancel := context.WithTimeout(ctx, s.HandshakeTimeout)
	if err := setDeadline(connection, handshakeCtx, s.HandshakeTimeout); err != nil {
		cancel()
		return
	}
	err := connection.HandshakeContext(handshakeCtx)
	cancel()
	if err != nil {
		return
	}
	if _, err := InspectSecurity(connection.ConnectionState()); err != nil {
		return
	}
	if err := setDeadline(connection, ctx, s.IdleTimeout); err != nil {
		return
	}
	frame, err := ReadFrame(connection)
	if err != nil {
		return
	}
	if frame.Type != Hello {
		sendError(connection, 0, protocolError("expected HELLO"))
		return
	}
	var hello helloMetadata
	if err := DecodeMetadata(frame, &hello, "versions"); err != nil {
		sendError(connection, 0, err)
		return
	}
	seen := map[int]bool{}
	if len(hello.Versions) == 0 || len(hello.Versions) > 16 {
		sendError(connection, 0, protocolError("invalid version offer"))
		return
	}
	for _, version := range hello.Versions {
		if version < 1 || version > 65535 || seen[version] {
			sendError(connection, 0, protocolError("invalid version offer"))
			return
		}
		seen[version] = true
	}
	if !seen[ProtocolVersion] {
		sendError(connection, 0, &RemoteError{"UNSUPPORTED_VERSION", "no common application version"})
		return
	}
	if err := send(connection, Welcome, 0, welcomeMetadata{ProtocolVersion, MaxChunkSize}, nil); err != nil {
		return
	}
	var lastID uint32
	var requestCount uint32
	for {
		if err := setDeadline(connection, ctx, s.IdleTimeout); err != nil {
			return
		}
		frame, err := ReadFrame(connection)
		if err != nil {
			return
		}
		if frame.Type == Close {
			if err := DecodeMetadata(frame, &struct{}{}); err != nil {
				sendError(connection, 0, err)
			}
			return
		}
		if frame.Type != Request || frame.RequestID <= lastID {
			sendError(connection, frame.RequestID, protocolError("expected a new, increasing request ID"))
			return
		}
		lastID = frame.RequestID
		var request requestMetadata
		if err := DecodeMetadata(frame, &request, "authority", "path", "query", "operation"); err != nil {
			sendError(connection, lastID, err)
			return
		}
		if err := ValidateAuthority(request.Authority); err != nil {
			sendError(connection, lastID, protocolError("invalid authority"))
			return
		}
		if request.Authority != s.Authority {
			sendError(connection, lastID, &RemoteError{"UNKNOWN_AUTHORITY", "this server does not serve that authority"})
			return
		}
		if request.Operation != "FETCH" {
			sendError(connection, lastID, &RemoteError{"UNSUPPORTED_OPERATION", "only FETCH is supported in V2"})
			return
		}
		if err := ValidateResource(request.Path, request.Query); err != nil {
			sendError(connection, lastID, protocolError("invalid resource"))
			return
		}
		if requestCount >= s.MaxRequestsPerSession {
			sendError(connection, lastID, &RemoteError{"SESSION_LIMIT", "session request limit reached; open a new connection"})
			return
		}
		if !peers.allowRequest(peer, time.Now()) {
			sendError(connection, lastID, &RemoteError{"RATE_LIMITED", "peer request rate limit reached"})
			return
		}
		requestCount++
		transferCtx, cancel := context.WithTimeout(ctx, s.Timeout)
		if err := setDeadline(connection, transferCtx, s.Timeout); err != nil {
			cancel()
			return
		}
		err = s.transfer(transferCtx, connection, lastID, request)
		cancel()
		if err != nil {
			sendError(connection, lastID, err)
			return
		}
	}
}

func (s *Server) transfer(ctx context.Context, connection net.Conn, id uint32, request requestMetadata) error {
	resource, err := s.Handler.Open(ctx, request.Path, request.Query)
	if err != nil {
		return err
	}
	if resource.Body == nil {
		return errors.New("provider returned no body")
	}
	defer resource.Body.Close()
	stop := context.AfterFunc(ctx, func() { resource.Body.Close() })
	defer stop()
	if resource.Size < 0 || resource.Size > MaxResourceSize || !validateMediaType(resource.MediaType) {
		return errors.New("invalid resource from provider")
	}
	if resource.Size > s.MaxBytes {
		return &RemoteError{"TOO_LARGE", "resource exceeds the server limit"}
	}
	if err := send(connection, Response, id, responseMetadata{resource.MediaType, resource.Size}, nil); err != nil {
		return err
	}
	hash := sha256.New()
	buffer := make([]byte, MaxChunkSize)
	var total int64
	for total < resource.Size {
		if err := ctx.Err(); err != nil {
			return err
		}
		remaining := resource.Size - total
		length := int64(len(buffer))
		if remaining < length {
			length = remaining
		}
		n, err := io.ReadFull(resource.Body, buffer[:length])
		if err != nil {
			return &RemoteError{"RESOURCE_CHANGED", "resource ended before its announced size"}
		}
		if err := send(connection, Data, id, struct{}{}, buffer[:n]); err != nil {
			return err
		}
		hash.Write(buffer[:n])
		total += int64(n)
	}
	var extra [1]byte
	n, err := io.ReadFull(resource.Body, extra[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		return &RemoteError{"RESOURCE_CHANGED", "resource size changed during transfer"}
	}
	return send(connection, End, id, endMetadata{total, hex.EncodeToString(hash.Sum(nil))}, nil)
}

func sendError(writer net.Conn, id uint32, cause error) {
	remote := &RemoteError{"INTERNAL_ERROR", "resource provider failed"}
	if errors.Is(cause, ErrProtocol) {
		remote = &RemoteError{"PROTOCOL_ERROR", "invalid DEEP message"}
	}
	var specified *RemoteError
	if errors.As(cause, &specified) && ValidateRemoteError(specified) == nil {
		remote = specified
	}
	if err := writer.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return
	}
	_ = send(writer, Error, id, remote, nil)
}

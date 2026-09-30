// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

const ApplicationProfile = "app/1"
const MaxApplicationRequestBytes int64 = 1 << 20
const MaxApplicationResponseBytes int64 = 16 << 20

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type ApplicationRequest struct {
	Method  string   `json:"method"`
	Headers []Header `json:"headers"`
	Body    []byte   `json:"body"`
}
type ApplicationResponse struct {
	Status   int
	Headers  []Header
	Resource Resource
}
type ApplicationHandler interface {
	Exchange(context.Context, string, string, ApplicationRequest) (ApplicationResponse, error)
}
type ApplicationResult struct {
	Result
	Status  int      `json:"status"`
	Headers []Header `json:"headers"`
}
type applicationContinue struct {
	Profile string `json:"profile"`
	MaxBody int64  `json:"max_body"`
}
type applicationRequestMetadata struct {
	Method  string   `json:"method"`
	Headers []Header `json:"headers"`
	Size    int64    `json:"size"`
}
type applicationResponseMetadata struct {
	Status    int      `json:"status"`
	Headers   []Header `json:"headers"`
	MediaType string   `json:"media_type"`
	Size      int64    `json:"size"`
}

func ValidApplicationMethod(method string) bool {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		return true
	}
	return false
}

// Header lists preserve duplicate response fields such as Set-Cookie. Names are
// canonical lowercase tokens; all values are bounded printable ASCII.
func ValidateApplicationHeaders(headers []Header) error {
	if headers == nil || len(headers) > 64 {
		return protocolError("invalid application header count")
	}
	total := 0
	for _, h := range headers {
		if len(h.Name) == 0 || len(h.Name) > 64 || len(h.Value) > 4096 {
			return protocolError("invalid application header size")
		}
		for _, c := range h.Name {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_"+string(rune(96))+"|~", c)) {
				return protocolError("invalid application header name")
			}
		}
		for _, c := range h.Value {
			if c < 32 || c > 126 {
				return protocolError("invalid application header value")
			}
		}
		total += len(h.Name) + len(h.Value)
	}
	if total > 6144 {
		return protocolError("application headers exceed limit")
	}
	return nil
}

func sendBody(ctx context.Context, c net.Conn, id uint32, body io.Reader, size int64) error {
	hash := sha256.New()
	buffer := make([]byte, MaxChunkSize)
	var total int64
	for total < size {
		if err := ctx.Err(); err != nil {
			return err
		}
		length := min(int64(len(buffer)), size-total)
		n, err := io.ReadFull(body, buffer[:length])
		if err != nil {
			return &RemoteError{"RESOURCE_CHANGED", "body ended before its announced size"}
		}
		if err = send(c, Data, id, struct{}{}, buffer[:n]); err != nil {
			return err
		}
		hash.Write(buffer[:n])
		total += int64(n)
	}
	var extra [1]byte
	if n, err := io.ReadFull(body, extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return &RemoteError{"RESOURCE_CHANGED", "body size changed during transfer"}
	}
	return send(c, End, id, endMetadata{total, hex.EncodeToString(hash.Sum(nil))}, nil)
}

func receiveBody(ctx context.Context, c net.Conn, id uint32, size int64, destination io.Writer) (string, error) {
	hash := sha256.New()
	var received int64
	for {
		frame, err := ReadFrame(c)
		if err != nil {
			return "", err
		}
		if frame.RequestID != id {
			return "", protocolError("body request ID mismatch")
		}
		switch frame.Type {
		case Data:
			if err := DecodeMetadata(frame, &struct{}{}); err != nil {
				return "", err
			}
			if int64(len(frame.Body)) > size-received {
				return "", protocolError("received more bytes than announced")
			}
			if err := writeAll(destination, frame.Body); err != nil {
				return "", err
			}
			hash.Write(frame.Body)
			received += int64(len(frame.Body))
		case End:
			var ending endMetadata
			if err := DecodeMetadata(frame, &ending, "size", "sha256"); err != nil {
				return "", err
			}
			digest := hex.EncodeToString(hash.Sum(nil))
			if received != size || ending.Size != received || ending.SHA256 != digest {
				return "", protocolError("body size or SHA-256 mismatch")
			}
			return digest, ctx.Err()
		case Error:
			return "", expect(frame, End, id)
		default:
			return "", protocolError("expected DATA or END")
		}
	}
}

func (c *Client) Exchange(ctx context.Context, value string, request ApplicationRequest, destination io.Writer) (ApplicationResult, error) {
	session, err := c.Dial(ctx, value)
	if err != nil {
		return ApplicationResult{}, err
	}
	defer session.Close()
	return session.Exchange(ctx, value, request, destination)
}

// Exchange never retries a submitted request. A lost response does not imply
// that a backend action failed; callers must not repeat writes automatically.
func (s *Session) Exchange(ctx context.Context, value string, request ApplicationRequest, destination io.Writer) (result ApplicationResult, err error) {
	if destination == nil || !ValidApplicationMethod(request.Method) || int64(len(request.Body)) > MaxApplicationRequestBytes {
		return result, errors.New("invalid application request")
	}
	if request.Headers == nil {
		request.Headers = []Header{}
	}
	if err = ValidateApplicationHeaders(request.Headers); err != nil {
		return result, err
	}
	if (request.Method == "GET" || request.Method == "HEAD") && len(request.Body) != 0 {
		return result, errors.New("GET and HEAD must not carry a body")
	}
	uri, err := ParseURI(value)
	if err != nil {
		return result, err
	}
	if uri.Authority != s.authority {
		return result, errors.New("session belongs to a different authority")
	}
	if !s.mutex.TryLock() {
		return result, errors.New("session is busy")
	}
	defer s.mutex.Unlock()
	if s.closed.Load() {
		return result, net.ErrClosed
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if s.nextID == 0 {
		return result, errors.New("request IDs exhausted")
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
	if err = send(s.connection, Request, id, requestMetadata{uri.Authority, uri.Path, uri.Query, "EXCHANGE"}, nil); err != nil {
		return result, err
	}
	frame, err := ReadFrame(s.connection)
	if err != nil {
		return result, err
	}
	if err = expect(frame, Continue, id); err != nil {
		return result, err
	}
	var ready applicationContinue
	if err = DecodeMetadata(frame, &ready, "profile", "max_body"); err != nil {
		return result, err
	}
	if ready.Profile != ApplicationProfile || ready.MaxBody != MaxApplicationRequestBytes {
		return result, protocolError("unsupported application profile")
	}
	metadata := applicationRequestMetadata{request.Method, request.Headers, int64(len(request.Body))}
	if err = send(s.connection, Request, id, metadata, nil); err != nil {
		return result, err
	}
	if err = sendBody(ctx, s.connection, id, bytes.NewReader(request.Body), metadata.Size); err != nil {
		return result, err
	}
	frame, err = ReadFrame(s.connection)
	if err != nil {
		return result, err
	}
	if err = expect(frame, Response, id); err != nil {
		return result, err
	}
	var response applicationResponseMetadata
	if err = DecodeMetadata(frame, &response, "status", "headers", "media_type", "size"); err != nil {
		return result, err
	}
	if response.Status < 200 || response.Status > 599 || !validateMediaType(response.MediaType) || response.Size < 0 || response.Size > min(s.maxBytes, MaxApplicationResponseBytes) {
		return result, protocolError("invalid application response")
	}
	if request.Method == "HEAD" && response.Size != 0 {
		return result, protocolError("HEAD response has a body")
	}
	if err = ValidateApplicationHeaders(response.Headers); err != nil {
		return result, err
	}
	digest, err := receiveBody(ctx, s.connection, id, response.Size, destination)
	if err != nil {
		return result, err
	}
	if err = s.connection.SetDeadline(time.Time{}); err != nil {
		return result, err
	}
	return ApplicationResult{Result{response.MediaType, response.Size, digest, s.Security}, response.Status, response.Headers}, nil
}

func (s *Server) exchange(ctx context.Context, c net.Conn, id uint32, target requestMetadata) error {
	if err := send(c, Continue, id, applicationContinue{ApplicationProfile, MaxApplicationRequestBytes}, nil); err != nil {
		return err
	}
	frame, err := ReadFrame(c)
	if err != nil {
		return err
	}
	if err = expect(frame, Request, id); err != nil {
		return err
	}
	var metadata applicationRequestMetadata
	if err = DecodeMetadata(frame, &metadata, "method", "headers", "size"); err != nil {
		return err
	}
	if !ValidApplicationMethod(metadata.Method) || metadata.Size < 0 || metadata.Size > MaxApplicationRequestBytes {
		return protocolError("invalid application request")
	}
	if (metadata.Method == "GET" || metadata.Method == "HEAD") && metadata.Size != 0 {
		return protocolError("GET and HEAD must not carry a body")
	}
	if err = ValidateApplicationHeaders(metadata.Headers); err != nil {
		return err
	}
	var body bytes.Buffer
	if _, err = receiveBody(ctx, c, id, metadata.Size, &body); err != nil {
		return err
	}
	request := ApplicationRequest{metadata.Method, metadata.Headers, body.Bytes()}
	var response ApplicationResponse
	if handler, ok := s.Handler.(ApplicationHandler); ok {
		response, err = handler.Exchange(ctx, target.Path, target.Query, request)
	} else if request.Method == "GET" || request.Method == "HEAD" {
		var resource Resource
		resource, err = s.Handler.Open(ctx, target.Path, target.Query)
		if err == nil {
			response = ApplicationResponse{200, []Header{}, resource}
		}
	} else {
		response = ApplicationResponse{405, []Header{{"allow", "GET, HEAD"}}, Resource{io.NopCloser(strings.NewReader("This service only supports GET and HEAD.")), "text/plain; charset=utf-8", int64(len("This service only supports GET and HEAD."))}}
	}
	if err != nil {
		return err
	}
	if response.Resource.Body == nil {
		return errors.New("application provider returned no body")
	}
	defer response.Resource.Body.Close()
	stop := context.AfterFunc(ctx, func() { response.Resource.Body.Close() })
	defer stop()
	if response.Headers == nil {
		response.Headers = []Header{}
	}
	if err = ValidateApplicationHeaders(response.Headers); err != nil {
		return err
	}
	if response.Status < 200 || response.Status > 599 || !validateMediaType(response.Resource.MediaType) || response.Resource.Size < 0 || response.Resource.Size > min(s.MaxBytes, MaxApplicationResponseBytes) {
		return errors.New("invalid application provider response")
	}
	payload := response.Resource.Body
	size := response.Resource.Size
	if request.Method == "HEAD" {
		payload = io.NopCloser(bytes.NewReader(nil))
		size = 0
	}
	if err = send(c, Response, id, applicationResponseMetadata{response.Status, response.Headers, response.Resource.MediaType, size}, nil); err != nil {
		return err
	}
	return sendBody(ctx, c, id, payload, size)
}

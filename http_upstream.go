// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HTTPHandler is an optional app/1 provider for one operator-selected loopback
// service. DEEP framing, identity and transport remain independent of HTTP.
type HTTPHandler struct {
	target    *url.URL
	authority string
	transport *http.Transport
	client    *http.Client
	slots     chan struct{}
}

func ValidateHTTPUpstream(address string) error {
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("upstream must be http://127.0.0.1:port or http://[::1]:port")
	}
	ip := net.ParseIP(u.Hostname())
	port, err := strconv.Atoi(u.Port())
	if ip == nil || !ip.IsLoopback() || err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != u.Port() {
		return errors.New("upstream requires a numeric loopback address and a port between 1 and 65535")
	}
	return nil
}

func NewHTTPHandler(address, authority string) (*HTTPHandler, error) {
	if err := ValidateHTTPUpstream(address); err != nil {
		return nil, err
	}
	if err := ValidateAuthority(authority); err != nil {
		return nil, err
	}
	target, _ := url.Parse(address)
	// Fresh loopback connections prevent net/http from silently replaying a
	// submitted action after a lost response, even with Idempotency-Key.
	transport := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 8192,
		ResponseHeaderTimeout: 15 * time.Second, IdleConnTimeout: 30 * time.Second, MaxIdleConnsPerHost: 8,
		DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	h := &HTTPHandler{target: target, authority: authority, transport: transport, slots: make(chan struct{}, 8)}
	h.client = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return h, nil
}
func (h *HTTPHandler) Close() error { h.transport.CloseIdleConnections(); return nil }

func (h *HTTPHandler) Open(ctx context.Context, path, query string) (Resource, error) {
	response, err := h.Exchange(ctx, path, query, ApplicationRequest{Method: "GET", Headers: []Header{}})
	if err != nil {
		return Resource{}, err
	}
	if response.Status != 200 {
		response.Resource.Body.Close()
		return Resource{}, &RemoteError{"NOT_FOUND", "application resource requires app/1 (use deep request or the updated viewer)"}
	}
	return response.Resource, nil
}

var hopHeaders = map[string]bool{
	"connection": true, "keep-alive": true, "proxy-authenticate": true, "proxy-authorization": true,
	"te": true, "trailer": true, "transfer-encoding": true, "upgrade": true, "content-length": true,
}

func blockedHeaders(headers []Header) map[string]bool {
	result := make(map[string]bool, len(hopHeaders))
	for k, v := range hopHeaders {
		result[k] = v
	}
	for _, h := range headers {
		if h.Name == "connection" {
			for _, name := range strings.Split(h.Value, ",") {
				result[strings.ToLower(strings.TrimSpace(name))] = true
			}
		}
	}
	return result
}
func (h *HTTPHandler) backendURL(value string) string {
	u, err := url.Parse(value)
	if err != nil {
		return value
	}
	if u.Scheme == "deep" && u.Host == h.authority {
		u.Scheme = "http"
		return u.String()
	}
	return value
}
func (h *HTTPHandler) location(value string) string {
	u, err := url.Parse(value)
	if err != nil {
		return value
	}
	if (u.Scheme == "http" || u.Scheme == "https" || u.Scheme == "") && (u.Host == h.target.Host || u.Host == h.authority) {
		u.Scheme = "deep"
		u.Host = h.authority
		return u.String()
	}
	return value
}

type heldBody struct {
	*bytes.Reader
	once    sync.Once
	release func()
}

func (b *heldBody) Close() error { b.once.Do(b.release); return nil }

func (h *HTTPHandler) Exchange(ctx context.Context, path, query string, request ApplicationRequest) (ApplicationResponse, error) {
	if err := ValidateResource(path, query); err != nil {
		return ApplicationResponse{}, err
	}
	if !ValidApplicationMethod(request.Method) || int64(len(request.Body)) > MaxApplicationRequestBytes {
		return ApplicationResponse{}, errors.New("invalid application request")
	}
	if (request.Method == "GET" || request.Method == "HEAD") && len(request.Body) != 0 {
		return ApplicationResponse{}, errors.New("GET and HEAD must not carry a body")
	}
	if request.Headers == nil {
		request.Headers = []Header{}
	}
	if err := ValidateApplicationHeaders(request.Headers); err != nil {
		return ApplicationResponse{}, err
	}
	select {
	case h.slots <- struct{}{}:
	case <-ctx.Done():
		return ApplicationResponse{}, ctx.Err()
	}
	release := func() { <-h.slots }
	owned := true
	defer func() {
		if owned {
			release()
		}
	}()
	decoded, err := url.PathUnescape(path)
	if err != nil {
		return ApplicationResponse{}, err
	}
	target := *h.target
	target.Path = decoded
	target.RawPath = path
	target.RawQuery = query
	r, err := http.NewRequestWithContext(ctx, request.Method, target.String(), bytes.NewReader(request.Body))
	if err != nil {
		return ApplicationResponse{}, err
	}
	// The connection destination is fixed above. Host identifies the DEEP site.
	r.Host = h.authority
	blocked := blockedHeaders(request.Headers)
	for _, header := range request.Headers {
		if blocked[header.Name] || header.Name == "host" || header.Name == "accept-encoding" || header.Name == "forwarded" || strings.HasPrefix(header.Name, "x-forwarded-") {
			continue
		}
		value := header.Value
		if header.Name == "origin" || header.Name == "referer" {
			value = h.backendURL(value)
		}
		r.Header.Add(header.Name, value)
	}
	r.Header.Set("Accept-Encoding", "identity")
	r.Header.Set("X-Forwarded-Host", h.authority)
	r.Header.Set("X-Forwarded-Proto", "deep")
	response, err := h.client.Do(r)
	if err != nil {
		return ApplicationResponse{}, fmt.Errorf("local application unavailable: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 599 {
		return ApplicationResponse{}, errors.New("unsupported upstream response status")
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return ApplicationResponse{}, errors.New("upstream must honor Accept-Encoding: identity")
	}
	if response.ContentLength > MaxApplicationResponseBytes && request.Method != "HEAD" {
		return ApplicationResponse{}, errors.New("application response exceeds 16 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxApplicationResponseBytes+1))
	if err != nil {
		return ApplicationResponse{}, err
	}
	if int64(len(data)) > MaxApplicationResponseBytes {
		return ApplicationResponse{}, errors.New("application response exceeds 16 MiB")
	}
	mediaType := response.Header.Get("Content-Type")
	if mediaType == "" {
		mediaType = http.DetectContentType(data)
	}
	if !validateMediaType(mediaType) {
		return ApplicationResponse{}, errors.New("invalid upstream media type")
	}
	raw := []Header{}
	for name, values := range response.Header {
		for _, value := range values {
			raw = append(raw, Header{strings.ToLower(name), value})
		}
	}
	blocked = blockedHeaders(raw)
	headers := []Header{}
	for _, header := range raw {
		if blocked[header.Name] || header.Name == "content-type" || header.Name == "content-encoding" {
			continue
		}
		if header.Name == "location" {
			header.Value = h.location(header.Value)
		}
		headers = append(headers, header)
	}
	if err := ValidateApplicationHeaders(headers); err != nil {
		return ApplicationResponse{}, err
	}
	owned = false
	return ApplicationResponse{response.StatusCode, headers, Resource{&heldBody{Reader: bytes.NewReader(data), release: release}, mediaType, int64(len(data))}}, nil
}

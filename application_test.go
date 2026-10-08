// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestApplicationPortSession(t *testing.T) {
	var writes atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if host, _, err := net.SplitHostPort(r.Host); err != nil || host != "127.0.0.1" {
			t.Error("local upstream host missing")
		}
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Forwarded-Host") != "node.alpha" {
			t.Error("unsafe forwarded headers")
		}
		if r.Header.Get("Origin") != "" && r.Header.Get("Origin") != "http://"+r.Host {
			t.Error("origin not adapted")
		}
		switch r.URL.Path {
		case "/login":
			writes.Add(1)
			if err := r.ParseForm(); err != nil || r.Form.Get("name") != "Emi" || r.URL.Query().Get("q") != "a+b" {
				t.Error("form/query corrupted")
			}
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "secret", Path: "/", HttpOnly: true, Secure: true})
			http.SetCookie(w, &http.Cookie{Name: "theme", Value: "dark", Path: "/"})
			w.Header().Set("Location", "http://"+r.Host+"/account")
			w.WriteHeader(303)
		case "/account":
			c, err := r.Cookie("session")
			if err != nil || c.Value != "secret" {
				w.WriteHeader(401)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, "logged in")
		case "/outside":
			w.Header().Set("Location", "http://192.0.2.1/private")
			w.WriteHeader(302)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	handler, err := NewHTTPHandler(upstream.URL, "node.alpha")
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	endpoint := startResourceServer(t, "node.alpha", handler)
	client := clientFor(t, "node.alpha", endpoint)
	session, err := client.Dial(context.Background(), "deep://node.alpha/")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var body bytes.Buffer
	result, err := session.Exchange(context.Background(), "deep://node.alpha/login?q=a%2Bb", ApplicationRequest{"POST", []Header{
		{"content-type", "application/x-www-form-urlencoded"}, {"origin", "deep://node.alpha"},
		{"proxy-authorization", "must not leak"}, {"x-forwarded-host", "attacker.example"},
	}, []byte("name=Emi")}, &body)
	if err != nil {
		t.Fatal(err)
	}
	cookies := 0
	redirect := ""
	for _, h := range result.Headers {
		if h.Name == "set-cookie" {
			cookies++
		}
		if h.Name == "location" {
			redirect = h.Value
		}
	}
	if result.Status != 303 || cookies != 2 || redirect != "deep://node.alpha/account" || writes.Load() != 1 {
		t.Fatalf("unexpected login result: %+v", result)
	}
	body.Reset()
	result, err = session.Exchange(context.Background(), redirect, ApplicationRequest{"GET", []Header{{"cookie", "session=secret"}}, nil}, &body)
	if err != nil || result.Status != 200 || body.String() != "logged in" || !result.Security.PostQuantumAuthentication || !result.Security.PostQuantumKeyExchange {
		t.Fatalf("session failed: %+v %v", result, err)
	}
	for _, check := range []struct {
		method, path string
		status       int
	}{{"HEAD", "/account", 200}, {"GET", "/missing", 404}, {"GET", "/outside", 302}} {
		body.Reset()
		result, err = session.Exchange(context.Background(), "deep://node.alpha"+check.path, ApplicationRequest{check.method, []Header{{"cookie", "session=secret"}}, nil}, &body)
		if err != nil || result.Status != check.status {
			t.Fatalf("%s: %+v %v", check.path, result, err)
		}
		if check.method == "HEAD" && body.Len() != 0 {
			t.Fatal("HEAD transferred a body")
		}
	}
}

func TestHTTPUpstreamRejectsUnsafeTargets(t *testing.T) {
	for _, target := range []string{"http://192.0.2.1:5000", "http://127.0.0.1", "http://127.0.0.1:0", "http://u:p@127.0.0.1:5000", "http://127.0.0.1:5000/path", "http://127.0.0.1:5000?x=1", "http://127.0.0.1:5000/#fragment"} {
		if ValidateHTTPUpstream(target) == nil {
			t.Errorf("accepted %s", target)
		}
	}
	for _, target := range []string{"http://127.0.0.1:5000", "http://[::1]:5000", "http://localhost:5000", "https://localhost:5000", "https://127.0.0.1:5000"} {
		if err := ValidateHTTPUpstream(target); err != nil {
			t.Fatal(err)
		}
	}
}

func TestApplicationRejectsUnverifiedUpload(t *testing.T) {
	for _, bad := range []string{"digest", "oversized", "wrong_id", "missing_field"} {
		t.Run(bad, func(t *testing.T) {
			var calls atomic.Int32
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			left.SetDeadline(time.Now().Add(3 * time.Second))
			right.SetDeadline(time.Now().Add(3 * time.Second))
			server := &Server{Handler: HandlerFunc(func(context.Context, string, string) (Resource, error) { calls.Add(1); return resourceBytes(nil), nil })}
			done := make(chan error, 1)
			go func() {
				done <- server.exchange(context.Background(), left, 7, requestMetadata{"node.alpha", "/", "", "EXCHANGE"})
			}()
			if f, err := ReadFrame(right); err != nil || f.Type != Continue {
				t.Fatalf("continue: %v", err)
			}
			size := int64(0)
			if bad == "oversized" {
				size = MaxApplicationRequestBytes + 1
			}
			if bad == "missing_field" {
				send(right, Request, 7, map[string]any{"method": "GET", "size": 0}, nil)
			} else {
				send(right, Request, 7, applicationRequestMetadata{"GET", []Header{}, size}, nil)
			}
			if bad == "digest" {
				send(right, End, 7, endMetadata{0, strings.Repeat("0", 64)}, nil)
			}
			if bad == "wrong_id" {
				send(right, End, 8, endMetadata{}, nil)
			}
			if err := <-done; err == nil {
				t.Fatal("invalid upload accepted")
			}
			if calls.Load() != 0 {
				t.Fatal("handler invoked before upload verification")
			}
		})
	}
}

func TestApplicationStaticCompatibilityAndLimits(t *testing.T) {
	endpoint := startResourceServer(t, "node.alpha", HandlerFunc(func(context.Context, string, string) (Resource, error) { return resourceBytes([]byte("static")), nil }))
	client := clientFor(t, "node.alpha", endpoint)
	for _, method := range []string{"GET", "HEAD", "POST"} {
		var body bytes.Buffer
		result, err := client.Exchange(context.Background(), "deep://node.alpha/", ApplicationRequest{Method: method}, &body)
		if err != nil {
			t.Fatal(err)
		}
		if method == "GET" && body.String() != "static" {
			t.Fatal("static GET")
		}
		if method == "POST" && result.Status != 405 {
			t.Fatal("static writes accepted")
		}
		if method == "HEAD" && body.Len() != 0 {
			t.Fatal("static HEAD")
		}
	}
	for _, r := range []ApplicationRequest{{Method: "CONNECT"}, {Method: "POST", Body: make([]byte, MaxApplicationRequestBytes+1)}, {Method: "GET", Body: []byte("bad")}, {Method: "GET", Headers: []Header{{"cookie", "x\r\ninjection"}}}} {
		if _, err := client.Exchange(context.Background(), "deep://node.alpha/", r, io.Discard); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
}

func TestHTTPUpstreamResponseBounds(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/compressed" {
			w.Header().Set("Content-Encoding", "gzip")
			return
		}
		w.Header().Set("Content-Length", "16777217")
	}))
	defer upstream.Close()
	h, err := NewHTTPHandler(upstream.URL, "node.alpha")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	for _, path := range []string{"/large", "/compressed"} {
		if r, err := h.Exchange(context.Background(), path, "", ApplicationRequest{"GET", []Header{}, nil}); err == nil {
			r.Resource.Body.Close()
			t.Fatal("invalid upstream response accepted")
		}
	}
}

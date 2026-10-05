// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestHTTPUpstreamDoesNotReplaySubmittedRequests(t *testing.T) {
	for _, body := range []string{"", "action=commit"} {
		t.Run(body, func(t *testing.T) {
			var submissions atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				if r.Method == "POST" {
					if r.Header.Get("Idempotency-Key") != "caller-provided" {
						t.Error("caller header lost")
					}
					if submissions.Add(1) == 1 {
						connection, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						connection.Close() // The action ran, but its response was lost.
						return
					}
				}
				w.WriteHeader(204)
			}))
			defer upstream.Close()
			h, err := NewHTTPHandler(upstream.URL, "node.alpha")
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			warm, err := h.Exchange(context.Background(), "/warm", "", ApplicationRequest{"GET", []Header{}, nil})
			if err != nil {
				t.Fatal(err)
			}
			warm.Resource.Body.Close()
			result, err := h.Exchange(context.Background(), "/commit", "", ApplicationRequest{"POST", []Header{{"idempotency-key", "caller-provided"}}, []byte(body)})
			if err == nil {
				result.Resource.Body.Close()
				t.Error("lost response should be reported to caller")
			}
			if got := submissions.Load(); got != 1 {
				t.Fatalf("submitted action executed %d times; want 1", got)
			}
		})
	}
}

func TestHTTPUpstreamValidatesComponentsBeforeCallingBackend(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(204) }))
	defer upstream.Close()
	h, err := NewHTTPHandler(upstream.URL, "node.alpha")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	for _, test := range []struct{ path, query, method, body string }{
		{"relative", "", "GET", ""}, {"/path?embedded", "", "GET", ""}, {"/path#fragment", "", "GET", ""},
		{"/", "query#fragment", "GET", ""}, {"/", "", "GET", "unexpected"}, {"/", "", "HEAD", "unexpected"},
	} {
		result, err := h.Exchange(context.Background(), test.path, test.query, ApplicationRequest{test.method, []Header{}, []byte(test.body)})
		if err == nil {
			result.Resource.Body.Close()
			t.Errorf("accepted invalid direct API request: %+v", test)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached backend")
	}
}

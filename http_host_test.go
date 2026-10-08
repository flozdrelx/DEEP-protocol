// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPUpstreamRoutesLocalVirtualHosts(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost"} {
		t.Run(host, func(t *testing.T) {
			var localHost string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Like a host-matched Caddy site, an unmatched Host produces an
				// empty response even though the listening port is reachable.
				if r.Host != localHost {
					return
				}
				if r.Header.Get("X-Forwarded-Host") != "node.alpha" {
					t.Error("DEEP identity lost or caller forwarding header trusted")
				}
				if r.Header.Get("Origin") != "http://"+localHost ||
					r.Header.Get("Referer") != "http://"+localHost+"/page" {
					t.Error("local same-origin values do not match Host")
				}
				if r.URL.Path == "/style.css" {
					w.Header().Set("Content-Type", "text/css")
					io.WriteString(w, "body { color: red; }")
				} else {
					w.Header().Set("Content-Type", "text/html")
					io.WriteString(w, "<html><link rel='stylesheet' href='/style.css'>Local site</html>")
				}
			}))
			defer upstream.Close()
			_, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())
			localHost = net.JoinHostPort(host, port)
			handler, err := NewHTTPHandler("http://"+localHost, "node.alpha")
			if err != nil {
				t.Fatal(err)
			}
			defer handler.Close()
			for _, path := range []string{"/", "/style.css"} {
				response, err := handler.Exchange(context.Background(), path, "", ApplicationRequest{
					Method: "GET",
					Headers: []Header{
						{"host", "attacker.example"},
						{"x-forwarded-host", "attacker.example"},
						{"origin", "deep://node.alpha"},
						{"referer", "deep://node.alpha/page"},
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Resource.Body)
				response.Resource.Body.Close()
				if err != nil || response.Status != 200 || len(body) == 0 {
					t.Fatalf("local resource %s was blank: status=%d body=%q err=%v", path, response.Status, body, err)
				}
			}
		})
	}
}

func TestLocalHTTPSRequiresTrustedCertificate(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "Trusted local HTTPS")
	}))
	defer upstream.Close()
	handler, err := NewHTTPHandler(upstream.URL, "node.alpha")
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	response, err := handler.Exchange(context.Background(), "/", "", ApplicationRequest{Method: "GET"})
	if err == nil {
		response.Resource.Body.Close()
		t.Fatal("untrusted local HTTPS certificate was accepted")
	}
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	trustedHandler, err := NewHTTPHandler(upstream.URL, "node.alpha")
	if err != nil {
		t.Fatal(err)
	}
	defer trustedHandler.Close()
	trustedHandler.transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	response, err = trustedHandler.Exchange(context.Background(), "/", "", ApplicationRequest{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Resource.Body.Close()
	body, err := io.ReadAll(response.Resource.Body)
	if err != nil || string(body) != "Trusted local HTTPS" {
		t.Fatalf("trusted local HTTPS failed: %q %v", body, err)
	}
}

func TestHTTPUpstreamLocalhostIPv6(t *testing.T) {
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback unavailable")
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Host, "localhost:") {
			t.Error("localhost Host was not preserved")
		}
		io.WriteString(w, "IPv6 local site")
	}))
	server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	handler, err := NewHTTPHandler("http://localhost:"+port, "node.alpha")
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	response, err := handler.Exchange(context.Background(), "/", "", ApplicationRequest{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Resource.Body.Close()
	body, err := io.ReadAll(response.Resource.Body)
	if err != nil || string(body) != "IPv6 local site" {
		t.Fatalf("IPv6 localhost fallback failed: %q %v", body, err)
	}
}

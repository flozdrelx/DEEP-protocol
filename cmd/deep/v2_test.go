// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	deep "deepprotocol"
)

func newTestNode(t *testing.T, public bool) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "node")
	args := []string{"init", "--authority", "test.alpha", "--dir", directory}
	if public {
		args = append(args, "--public")
	}
	if err := run(context.Background(), args, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestPrivateNodeRequiresGeneratedClientAndPublicNodeDoesNot(t *testing.T) {
	for _, public := range []bool{false, true} {
		name := "private"
		if public {
			name = "public"
		}
		t.Run(name, func(t *testing.T) {
			directory := newTestNode(t, public)
			config, err := loadServerConfig(filepath.Join(directory, "server.json"))
			if err != nil {
				t.Fatal(err)
			}
			client, err := deep.LoadClientConfig(filepath.Join(directory, "client.json"))
			if err != nil {
				t.Fatal(err)
			}
			if public && client.Identity != nil {
				t.Fatal("public init generated unnecessary client credentials")
			}
			if !public && client.Identity == nil {
				t.Fatal("private init did not generate client credentials")
			}
			identity, err := tls.LoadX509KeyPair(config.Certificate, config.PrivateKey)
			if err != nil {
				t.Fatal(err)
			}
			transport := deep.ServerTLSConfig(identity)
			if !public {
				transport, err = deep.ServerTLSConfigWithClientPins(identity, config.AllowedClientPins)
				if err != nil {
					t.Fatal(err)
				}
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			server := &deep.Server{Authority: config.Authority, TLSConfig: transport,
				Handler: deep.HandlerFunc(func(context.Context, string, string) (deep.Resource, error) {
					return deep.Resource{Body: io.NopCloser(strings.NewReader("verified")), Size: 8, MediaType: "text/plain"}, nil
				}),
			}
			done := make(chan error, 1)
			go func() { done <- server.Serve(ctx, listener) }()
			defer func() {
				cancel()
				listener.Close()
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			pin, err := deep.IdentityPin(identity)
			if err != nil {
				t.Fatal(err)
			}
			registry := deep.NewRegistry()
			if err := registry.Register("alpha", deep.StaticAdapter{"test.alpha": {Address: listener.Addr().String(), PinSHA256: pin}}); err != nil {
				t.Fatal(err)
			}
			client.Registry = registry
			var output bytes.Buffer
			if _, err := client.Fetch(ctx, "deep://test.alpha/", &output); err != nil {
				t.Fatal(err)
			}
			if output.String() != "verified" {
				t.Fatal("wrong resource")
			}
			anonymous := deep.NewClient(registry)
			_, err = anonymous.Fetch(ctx, "deep://test.alpha/", io.Discard)
			if public && err != nil {
				t.Fatal(err)
			}
			if !public && err == nil {
				t.Fatal("private node admitted an anonymous client")
			}
		})
	}
}

func TestServerConfigRejectsAmbiguousAndUnsafeSettings(t *testing.T) {
	directory := newTestNode(t, false)
	path := filepath.Join(directory, "server.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	version := "\"version\": 2"
	cases := map[string]string{
		"duplicate":        strings.Replace(string(original), version, version+", \"version\": 2", 1),
		"wrong case":       strings.Replace(string(original), "\"version\"", "\"Version\"", 1),
		"null":             strings.Replace(string(original), version, "\"version\": null", 1),
		"missing mode":     strings.Replace(string(original), "\"access_mode\": \"private\",", "", 1),
		"unknown":          strings.Replace(string(original), version, version+", \"unrecognized\": true", 1),
		"V1":               strings.Replace(string(original), version, "\"version\": 1", 1),
		"negative limit":   strings.Replace(string(original), version, version+", \"max_bytes\": -1", 1),
		"excessive limit":  strings.Replace(string(original), version, version+", \"max_connections\": 4097", 1),
		"public with pins": strings.Replace(string(original), "\"private\"", "\"public\"", 1),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadServerConfig(path); err == nil {
				t.Fatal("accepted invalid server configuration")
			}
		})
	}
}

func TestServerRefusesIdentityOrConfigurationUnderContentRoot(t *testing.T) {
	directory := newTestNode(t, false)
	path := filepath.Join(directory, "server.json")
	config, err := loadServerConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateServingPaths(path, config); err != nil {
		t.Fatal(err)
	}
	config.Root = directory
	if err := validateServingPaths(path, config); err == nil {
		t.Fatal("accepted secret files under content root")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(directory, alias); err != nil {
		t.Log("symlink unavailable:", err)
		return
	}
	config.Root = alias
	if err := validateServingPaths(path, config); err == nil {
		t.Fatal("accepted a symlink to the secret directory")
	}
}

func TestClientInitAndInspectShowOnlyPublicInformation(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "client")
	args := []string{"client-init", "--authority", "guest.alpha", "--dir", directory}
	if err := run(context.Background(), args, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), args, io.Discard, io.Discard); err == nil {
		t.Fatal("overwrote client identity")
	}
	var output bytes.Buffer
	if err := run(context.Background(), []string{"inspect", "--certificate", filepath.Join(directory, "client.crt")}, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report["valid_now"] != true || len(report["pin_sha256"].(string)) != 64 {
		t.Fatal(report)
	}
	if strings.Contains(output.String(), "PRIVATE") {
		t.Fatal("inspect leaked private information")
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(directory, "client.crt"), filepath.Join(directory, "client.key"))
	if err != nil {
		t.Fatal(err)
	}
	expected, err := deep.IdentityPin(cert)
	if err != nil || report["pin_sha256"] != expected {
		t.Fatal("incorrect inspect pin")
	}
}

func TestTerminalOutputEscapesControlsAndBidi(t *testing.T) {
	input := "hello\n\x1b]52;c;secret\a\x1b[2J\rfake\u202etxt\x9b2J"
	got := terminalText(input)
	for _, forbidden := range []rune{'\x1b', '\a', '\r', '\u202e', '\x9b'} {
		if strings.ContainsRune(got, forbidden) {
			t.Fatalf("unescaped terminal control %U", forbidden)
		}
	}
	if !strings.HasPrefix(got, "hello\n") {
		t.Fatal("lost readable ordinary text")
	}
	var output bytes.Buffer
	if _, err := (safeWriter{&output}).Write([]byte(input)); err != nil {
		t.Fatal(err)
	}
	if output.String() != got {
		t.Fatal("unsafe diagnostic writer")
	}
}

func TestPreviewVerifiesThenEscapesAndRejectsOversizedContent(t *testing.T) {
	for _, oversize := range []bool{false, true} {
		t.Run(map[bool]string{false: "escape", true: "limit"}[oversize], func(t *testing.T) {
			content := []byte("\x1b]52;c;secret\ahello")
			if oversize {
				content = bytes.Repeat([]byte("x"), previewLimit+1)
			}
			client := testClient(t, content)
			endpoint, err := client.Registry.Resolve(context.Background(), "test.alpha")
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(t.TempDir(), "client.json")
			config := map[string]any{"version": 2, "networks": map[string]any{"alpha": map[string]any{"adapter": "static", "endpoints": map[string]deep.Endpoint{"test.alpha": endpoint}}}}
			if err := writeJSON(configPath, config); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = previewURI(ctx, "deep://test.alpha/", configPath, &output, io.Discard)
			if oversize {
				if err == nil || output.Len() != 0 {
					t.Fatal("oversized preview was displayed")
				}
			} else if err != nil || strings.ContainsRune(output.String(), '\x1b') || !strings.Contains(output.String(), "hello") {
				t.Fatalf("bad preview: %q %v", output.String(), err)
			}
		})
	}
}

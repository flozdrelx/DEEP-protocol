// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	deep "deepprotocol"
)

func TestInitCreatesUsableIdentityAndDoesNotOverwrite(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "node")
	var output bytes.Buffer
	args := []string{"init", "--authority", "test.alpha", "--dir", directory, "--address", "127.0.0.1:9761"}
	if err := run(context.Background(), args, &output, io.Discard); err != nil {
		t.Fatal(err)
	}
	config, err := loadServerConfig(filepath.Join(directory, "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := tls.LoadX509KeyPair(config.Certificate, config.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	registry, err := deep.LoadRegistry(filepath.Join(directory, "client.json"))
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := registry.Resolve(context.Background(), config.Authority)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if endpoint.PinSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("generated client pin does not match generated identity")
	}
	if err := run(context.Background(), args, io.Discard, io.Discard); err == nil {
		t.Fatal("init overwrote an existing directory")
	}
	keyAfter, err := os.ReadFile(config.PrivateKey)
	if err != nil || len(keyAfter) == 0 {
		t.Fatal("existing identity was damaged")
	}
}

func TestInitRejectsInvalidAddresses(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "127.0.0.1:http", "0.0.0.0:9761", "127.0.0.1:65536", "127.0.0.1:09761"} {
		t.Run(address, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "node")
			err := run(context.Background(), []string{"init", "--authority", "test.alpha", "--dir", directory, "--address", address}, io.Discard, io.Discard)
			if err == nil {
				t.Fatal("accepted invalid address")
			}
			if _, err := os.Stat(directory); !os.IsNotExist(err) {
				t.Fatal("invalid init left a directory")
			}
		})
	}
}

func TestFetchFilePublishesVerifiedContentAndPreservesExistingFile(t *testing.T) {
	content := bytes.Repeat([]byte{0, 1, 2, 255}, 50000)
	client := testClient(t, content)
	path := filepath.Join(t.TempDir(), "download.bin")
	result, err := fetchFile(context.Background(), client, "deep://test.alpha/", path)
	if err != nil {
		t.Fatal(err)
	}
	if result.Size != int64(len(content)) || !result.Security.PostQuantumKeyExchange {
		t.Fatalf("unexpected result: %+v", result)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatal("download differs from source")
	}
	if _, err := fetchFile(context.Background(), client, "deep://test.alpha/", path); err == nil {
		t.Fatal("existing output was overwritten")
	}
	files, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".deep-download-*"))
	if err != nil || len(files) != 0 {
		t.Fatal("temporary download remains")
	}
}

func TestFetchFileFailureLeavesNoOutput(t *testing.T) {
	client := testClient(t, bytes.Repeat([]byte("data"), 1000))
	client.MaxBytes = 10
	path := filepath.Join(t.TempDir(), "download.bin")
	if _, err := fetchFile(context.Background(), client, "deep://test.alpha/", path); err == nil {
		t.Fatal("oversize transfer succeeded")
	}
	files, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(files) != 0 {
		t.Fatal("failed download left output or temporary files")
	}
}

func TestCommandVersionAndHelp(t *testing.T) {
	for _, args := range [][]string{{}, {"--help"}, {"version"}, {"init", "--help"}, {"serve", "--help"}, {"fetch", "--help"}} {
		var output bytes.Buffer
		if err := run(context.Background(), args, &output, &output); err != nil {
			t.Fatal(err)
		}
		if output.Len() == 0 {
			t.Fatal("command did not print output")
		}
	}
	if err := run(context.Background(), []string{"open-uri", "deep://test.alpha/", "--output", "injected"}, io.Discard, io.Discard); err == nil {
		t.Fatal("URI command accepted extra options")
	}
}

func TestDemoNegotiatesPQCForBothNetworks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var output bytes.Buffer
	if err := demo(ctx, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Count(output.String(), "PQC key exchange: true") != 2 || strings.Count(output.String(), "Same session:") != 2 {
		t.Fatal(output.String())
	}
}

func testClient(t *testing.T, content []byte) *deep.Client {
	t.Helper()
	certPEM, keyPEM, pin, err := deep.GenerateIdentity("test.alpha", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := &deep.Server{
		Authority: "test.alpha", TLSConfig: deep.ServerTLSConfig(identity),
		Handler: deep.HandlerFunc(func(context.Context, string, string) (deep.Resource, error) {
			return deep.Resource{Body: io.NopCloser(bytes.NewReader(content)), MediaType: "application/octet-stream", Size: int64(len(content))}, nil
		}),
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})
	registry := deep.NewRegistry()
	if err := registry.Register("alpha", deep.StaticAdapter{"test.alpha": {Address: listener.Addr().String(), PinSHA256: pin}}); err != nil {
		t.Fatal(err)
	}
	return deep.NewClient(registry)
}

// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	deep "deepprotocol"
)

type serverConfig struct {
	Version                 int      `json:"version"`
	Authority               string   `json:"authority"`
	Listen                  string   `json:"listen"`
	Root                    string   `json:"root"`
	Certificate             string   `json:"certificate"`
	PrivateKey              string   `json:"private_key"`
	AccessMode              string   `json:"access_mode"`
	AllowedClientPins       []string `json:"allowed_client_pins,omitempty"`
	HandshakeTimeoutSeconds int      `json:"handshake_timeout_seconds,omitempty"`
	IdleTimeoutSeconds      int      `json:"idle_timeout_seconds,omitempty"`
	TransferTimeoutSeconds  int      `json:"transfer_timeout_seconds,omitempty"`
	SessionTimeoutSeconds   int      `json:"session_timeout_seconds,omitempty"`
	MaxConnections          int      `json:"max_connections,omitempty"`
	MaxConnectionsPerPeer   int      `json:"max_connections_per_peer,omitempty"`
	MaxRequestsPerSession   uint32   `json:"max_requests_per_session,omitempty"`
	MaxBytes                int64    `json:"max_bytes,omitempty"`
	RequestsPerMinute       int      `json:"requests_per_minute,omitempty"`
}

func loadServerConfig(path string) (serverConfig, error) {
	var config serverConfig
	file, err := os.Open(path)
	if err != nil {
		return config, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil {
		return config, err
	}
	if len(data) > 65536 {
		return config, errors.New("server.json exceeds 64 KiB")
	}
	if err := deep.DecodeConfigJSON(data, &config); err != nil {
		return config, fmt.Errorf("invalid V2 server configuration (see docs/MIGRATION-V2.md): %w", err)
	}
	if config.Version != 2 {
		return config, errors.New("DEEP V2 requires version 2 configuration and new ML-DSA-65 identities; see docs/MIGRATION-V2.md")
	}
	if config.Root == "" || config.Certificate == "" || config.PrivateKey == "" || config.Listen == "" {
		return config, errors.New("root, certificate, private_key, and listen must not be empty")
	}
	if err := deep.ValidateAuthority(config.Authority); err != nil {
		return config, err
	}
	if _, _, err := net.SplitHostPort(config.Listen); err != nil {
		return config, fmt.Errorf("invalid listen address: %w", err)
	}
	if config.AccessMode != "private" && config.AccessMode != "public" {
		return config, errors.New("access_mode must be private or public")
	}
	if config.AccessMode == "private" && len(config.AllowedClientPins) == 0 {
		return config, errors.New("private servers require a nonempty allowed_client_pins list")
	}
	if config.AccessMode == "public" && len(config.AllowedClientPins) != 0 {
		return config, errors.New("public servers must not set allowed_client_pins")
	}
	if len(config.AllowedClientPins) > deep.MaxClientPins {
		return config, fmt.Errorf("allowed_client_pins exceeds %d entries", deep.MaxClientPins)
	}
	for _, item := range []struct {
		name  string
		value int64
		max   int64
	}{
		{"handshake_timeout_seconds", int64(config.HandshakeTimeoutSeconds), 60},
		{"idle_timeout_seconds", int64(config.IdleTimeoutSeconds), 600},
		{"transfer_timeout_seconds", int64(config.TransferTimeoutSeconds), 3600},
		{"session_timeout_seconds", int64(config.SessionTimeoutSeconds), 86400},
		{"max_connections", int64(config.MaxConnections), 4096},
		{"max_connections_per_peer", int64(config.MaxConnectionsPerPeer), 4096},
		{"max_requests_per_session", int64(config.MaxRequestsPerSession), 1000000},
		{"max_bytes", config.MaxBytes, 1 << 40},
		{"requests_per_minute", int64(config.RequestsPerMinute), 1000000},
	} {
		if item.value < 0 || item.value > item.max {
			return config, fmt.Errorf("%s must be between 0 (default) and %d", item.name, item.max)
		}
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = 128
	}
	if config.MaxConnectionsPerPeer == 0 {
		config.MaxConnectionsPerPeer = min(16, config.MaxConnections)
	}
	if config.MaxConnectionsPerPeer > config.MaxConnections {
		return config, errors.New("max_connections_per_peer exceeds max_connections")
	}
	if config.HandshakeTimeoutSeconds == 0 {
		config.HandshakeTimeoutSeconds = 5
	}
	if config.IdleTimeoutSeconds == 0 {
		config.IdleTimeoutSeconds = 30
	}
	if config.TransferTimeoutSeconds == 0 {
		config.TransferTimeoutSeconds = 30
	}
	if config.SessionTimeoutSeconds == 0 {
		config.SessionTimeoutSeconds = 3600
	}
	if config.MaxRequestsPerSession == 0 {
		config.MaxRequestsPerSession = 1000
	}
	if config.MaxBytes == 0 {
		config.MaxBytes = 1 << 30
	}
	if config.RequestsPerMinute == 0 {
		config.RequestsPerMinute = 120
	}
	base := filepath.Dir(path)
	for _, value := range []*string{&config.Root, &config.Certificate, &config.PrivateKey} {
		if !filepath.IsAbs(*value) {
			*value = filepath.Join(base, *value)
		}
	}
	return config, nil
}

func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

func validateServingPaths(configPath string, config serverConfig) error {
	root, err := canonicalPath(config.Root)
	if err != nil {
		return fmt.Errorf("resolve content root: %w", err)
	}
	for _, sensitive := range []string{configPath, config.Certificate, config.PrivateKey} {
		path, err := canonicalPath(sensitive)
		if err != nil {
			return fmt.Errorf("resolve identity/configuration: %w", err)
		}
		compareRoot, comparePath := root, path
		if runtime.GOOS == "windows" {
			compareRoot, comparePath = strings.ToLower(root), strings.ToLower(path)
		}
		relative, err := filepath.Rel(compareRoot, comparePath)
		if err != nil {
			return err
		}
		if relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)) {
			return fmt.Errorf("identity and configuration files must be outside the served content root: %q", sensitive)
		}
	}
	return nil
}

func serveNode(ctx context.Context, args []string, out, diagnostic io.Writer) error {
	flags := newFlags("deep serve", diagnostic)
	path := flags.String("config", "server.json", "Server configuration")
	proceed, err := parseFlags(flags, args)
	if err != nil || !proceed {
		return err
	}
	config, err := loadServerConfig(*path)
	if err != nil {
		return err
	}
	if err := validateServingPaths(*path, config); err != nil {
		return err
	}
	identity, err := tls.LoadX509KeyPair(config.Certificate, config.PrivateKey)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	if err := deep.ValidateServerIdentity(identity, config.Authority); err != nil {
		return err
	}
	transport := deep.ServerTLSConfig(identity)
	if config.AccessMode == "private" {
		transport, err = deep.ServerTLSConfigWithClientPins(identity, config.AllowedClientPins)
		if err != nil {
			return err
		}
	}
	handler, err := deep.NewFileHandler(config.Root)
	if err != nil {
		return err
	}
	defer handler.Close()
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &deep.Server{
		Authority: config.Authority, TLSConfig: transport, Handler: handler,
		Timeout:          time.Duration(config.TransferTimeoutSeconds) * time.Second,
		HandshakeTimeout: time.Duration(config.HandshakeTimeoutSeconds) * time.Second,
		IdleTimeout:      time.Duration(config.IdleTimeoutSeconds) * time.Second,
		SessionTimeout:   time.Duration(config.SessionTimeoutSeconds) * time.Second,
		MaxConnections:   config.MaxConnections, MaxConnectionsPerPeer: config.MaxConnectionsPerPeer,
		MaxRequestsPerSession: config.MaxRequestsPerSession, MaxBytes: config.MaxBytes,
		RequestsPerMinute: config.RequestsPerMinute,
	}
	fmt.Fprintf(out, "DEEP %s listening on %s for deep://%s/\nTLS 1.3 / X25519MLKEM768 / ML-DSA-65 / ALPN deep/2; access: %s; Ctrl+C to stop.\n", deep.Version, listener.Addr(), config.Authority, config.AccessMode)
	err = server.Serve(ctx, listener)
	if ctx.Err() != nil && (err == nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed)) {
		return nil
	}
	return err
}

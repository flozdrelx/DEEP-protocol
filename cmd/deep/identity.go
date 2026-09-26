// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	deep "deepprotocol"
)

func createPrivateDirectory(path string) error {
	if err := os.Mkdir(path, 0700); err != nil {
		return fmt.Errorf("create new directory (existing directories are not overwritten): %w", err)
	}
	if err := protectDirectory(path); err != nil {
		_ = os.Remove(path) // Still empty: no identity was written before ACL protection.
		return fmt.Errorf("protect private directory: %w", err)
	}
	return nil
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

func initNode(args []string, out, diagnostic io.Writer) (err error) {
	flags := newFlags("deep init", diagnostic)
	authority := flags.String("authority", "", "Server identity in node.network format")
	dir := flags.String("dir", "", "New protected directory for identity, content, and configuration")
	address := flags.String("address", "127.0.0.1:9761", "host:port address for listening and connecting")
	public := flags.Bool("public", false, "Explicitly allow clients without a client certificate")
	proceed, err := parseFlags(flags, args)
	if err != nil || !proceed {
		return err
	}
	if *authority == "" || *dir == "" {
		return errors.New("init requires --authority and --dir")
	}
	if err := deep.ValidateAuthority(*authority); err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(*address)
	if err != nil || host == "" || port == "0" || port == "" {
		return errors.New("--address must be host:port with a nonzero port; use an address reachable by the client")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 || strconv.Itoa(portNumber) != port {
		return errors.New("port must be an integer between 1 and 65535")
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return errors.New("--address requires a specific address; you can later change listen in server.json to 0.0.0.0:port")
	}
	target, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	cert, key, pin, err := deep.GenerateIdentity(*authority, 365*24*time.Hour)
	if err != nil {
		return err
	}
	if err := deep.ValidateEndpoint(deep.Endpoint{Address: *address, PinSHA256: pin, Transport: "tcp"}); err != nil {
		return err
	}
	if err = createPrivateDirectory(target); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(target)
		}
	}()
	if err := os.Mkdir(filepath.Join(target, "content"), 0700); err != nil {
		return err
	}
	server := serverConfig{
		Version: 2, Authority: *authority, Listen: *address, Root: "content",
		Certificate: "identity.crt", PrivateKey: "identity.key", AccessMode: "private",
	}
	network := strings.Split(*authority, ".")[1]
	client := map[string]any{
		"version": 2,
		"networks": map[string]any{
			network: map[string]any{
				"adapter": "static",
				"endpoints": map[string]deep.Endpoint{
					*authority: {Address: *address, PinSHA256: pin, Transport: "tcp"},
				},
			},
		},
	}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"identity.crt", cert, 0644},
		{"identity.key", key, 0600},
		{filepath.Join("content", "index.txt"), []byte("Hello from deep://" + *authority + "/\nDEEP V2: native messages, hybrid post-quantum key exchange, and ML-DSA-65 authentication.\n"), 0644},
	}
	if *public {
		server.AccessMode = "public"
	} else {
		clientCert, clientKey, clientPin, err := deep.GenerateClientIdentity("client."+network, 365*24*time.Hour)
		if err != nil {
			return err
		}
		files = append(files, struct {
			name string
			data []byte
			mode os.FileMode
		}{"client.crt", clientCert, 0644},
			struct {
				name string
				data []byte
				mode os.FileMode
			}{"client.key", clientKey, 0600})
		server.AllowedClientPins = []string{clientPin}
		client["client_identity"] = map[string]string{"certificate": "client.crt", "private_key": "client.key"}
	}
	for _, file := range files {
		if err := os.WriteFile(filepath.Join(target, file.name), file.data, file.mode); err != nil {
			return err
		}
	}
	if err := writeJSON(filepath.Join(target, "server.json"), server); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(target, "client.json"), client); err != nil {
		return err
	}
	complete = true
	fmt.Fprintf(out, "Node created: %q\nAuthority: %s\nAccess: %s\nServer SPKI SHA-256 pin: %s\n", target, *authority, server.AccessMode, pin)
	fmt.Fprintf(out, "Server: deep serve --config %q\nClient:  deep fetch deep://%s/ --config %q --info\n", filepath.Join(target, "server.json"), *authority, filepath.Join(target, "client.json"))
	return nil
}

func initClient(args []string, out, diagnostic io.Writer) error {
	flags := newFlags("deep client-init", diagnostic)
	authority := flags.String("authority", "", "Client identity in client.network format")
	directory := flags.String("dir", "", "New protected directory for client credentials")
	proceed, err := parseFlags(flags, args)
	if err != nil || !proceed {
		return err
	}
	if *authority == "" || *directory == "" {
		return errors.New("client-init requires --authority and --dir")
	}
	cert, key, pin, err := deep.GenerateClientIdentity(*authority, 365*24*time.Hour)
	if err != nil {
		return err
	}
	target, err := filepath.Abs(*directory)
	if err != nil {
		return err
	}
	if err := createPrivateDirectory(target); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(target)
		}
	}()
	if err := os.WriteFile(filepath.Join(target, "client.crt"), cert, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(target, "client.key"), key, 0600); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(target, "identity.json"), map[string]any{
		"authority": *authority, "pin_sha256": pin,
		"client_identity": map[string]string{"certificate": "client.crt", "private_key": "client.key"},
	}); err != nil {
		return err
	}
	complete = true
	fmt.Fprintf(out, "Client identity created: %q\nAuthority: %s\nClient SPKI SHA-256 pin: %s\nAdd this public pin to the server's allowed_client_pins and restart the server.\nKeep client.key private; use client_identity from identity.json in your client configuration.\n", target, *authority, pin)
	return nil
}

func inspectCertificate(args []string, out, diagnostic io.Writer) error {
	flags := newFlags("deep inspect", diagnostic)
	path := flags.String("certificate", "", "PEM certificate to inspect (no private key needed)")
	proceed, err := parseFlags(flags, args)
	if err != nil || !proceed {
		return err
	}
	if *path == "" {
		return errors.New("inspect requires --certificate")
	}
	file, err := os.Open(*path)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil {
		return err
	}
	if len(data) > 65536 {
		return errors.New("certificate file exceeds 64 KiB")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return errors.New("expected exactly one PEM CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	now := time.Now()
	return json.NewEncoder(out).Encode(map[string]any{
		"subject": cert.Subject.String(), "authorities": cert.DNSNames,
		"public_key_algorithm": cert.PublicKeyAlgorithm.String(),
		"signature_algorithm":  cert.SignatureAlgorithm.String(),
		"pin_sha256":           hex.EncodeToString(digest[:]),
		"not_before":           cert.NotBefore.UTC().Format(time.RFC3339),
		"not_after":            cert.NotAfter.UTC().Format(time.RFC3339),
		"valid_now":            !now.Before(cert.NotBefore) && now.Before(cert.NotAfter),
		"usage":                cert.ExtKeyUsage,
	})
}

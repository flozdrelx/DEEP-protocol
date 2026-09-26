// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	deep "deepprotocol"
)

func demo(ctx context.Context, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	directory, err := os.MkdirTemp("", "deep-v2-demo-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	registry := deep.NewRegistry()
	clientCert, clientKey, clientPin, err := deep.GenerateClientIdentity("demo.alpha", time.Hour)
	if err != nil {
		return err
	}
	clientIdentity, err := tls.X509KeyPair(clientCert, clientKey)
	if err != nil {
		return err
	}
	var listeners []net.Listener
	var handlers []*deep.FileHandler
	var completions []chan error
	defer func() {
		cancel()
		for _, listener := range listeners {
			_ = listener.Close()
		}
		for _, completion := range completions {
			<-completion
		}
		for _, handler := range handlers {
			_ = handler.Close()
		}
	}()
	for _, network := range []string{"alpha", "beta"} {
		authority := "node." + network
		root := filepath.Join(directory, network)
		if err := os.Mkdir(root, 0700); err != nil {
			return err
		}
		content := []byte("Hello from deep://" + authority + "/\n")
		if err := os.WriteFile(filepath.Join(root, "index.txt"), content, 0600); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(root, "stream.bin"), bytes.Repeat([]byte(network+"\n"), 50000), 0600); err != nil {
			return err
		}
		certPEM, keyPEM, pin, err := deep.GenerateIdentity(authority, time.Hour)
		if err != nil {
			return err
		}
		identity, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return err
		}
		handler, err := deep.NewFileHandler(root)
		if err != nil {
			return err
		}
		handlers = append(handlers, handler)
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		listeners = append(listeners, listener)
		transport, err := deep.ServerTLSConfigWithClientPins(identity, []string{clientPin})
		if err != nil {
			return err
		}
		server := &deep.Server{Authority: authority, TLSConfig: transport, Handler: handler}
		completion := make(chan error, 1)
		completions = append(completions, completion)
		go func() { completion <- server.Serve(ctx, listener) }()
		if err := registry.Register(network, deep.StaticAdapter{authority: {Address: listener.Addr().String(), PinSHA256: pin, Transport: "tcp"}}); err != nil {
			return err
		}
	}
	client := deep.NewClient(registry)
	client.Identity = &clientIdentity
	fmt.Fprintln(out, "DEEP V2: two private networks, mutual ML-DSA-65 authentication, no HTTP.")
	for _, network := range []string{"alpha", "beta"} {
		uri := "deep://node." + network + "/"
		session, err := client.Dial(ctx, uri)
		if err != nil {
			return err
		}
		if err := demoSession(ctx, session, uri, out); err != nil {
			_ = session.Close()
			return err
		}
		if err := session.Close(); err != nil {
			return err
		}
	}
	fmt.Fprintln(out, "Demo complete; temporary servers and files will now be cleaned up.")
	return nil
}

func demoSession(ctx context.Context, session *deep.Session, uri string, out io.Writer) error {
	var content bytes.Buffer
	result, err := session.Fetch(ctx, uri, &content)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "\n%s\n%s", uri, content.String())
	fmt.Fprintf(out, "Negotiated: %s / %s / %s\nAuthentication: %s; PQC key exchange: %t\n", result.Security.TLSVersion, result.Security.KeyExchange, result.Security.CipherSuite, result.Security.Authentication, result.Security.PostQuantumKeyExchange)
	streamed, err := session.Fetch(ctx, uri+"stream.bin", io.Discard)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Same session: %d streamed bytes; SHA-256 %s\n", streamed.Size, streamed.SHA256)
	return nil
}

// SPDX-License-Identifier: Apache-2.0

// deep is the reference command-line client and server for DEEP V1.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	deep "deepprotocol"
)

const usage = `DEEP V1 - an HTTP-independent resource protocol

Usage:
  deep version
  deep demo
  deep init --authority node.alpha --dir node-alpha --address 127.0.0.1:9761
  deep serve --config node-alpha/server.json
  deep fetch deep://node.alpha/ --config node-alpha/client.json [--output file] [--info]
  deep open-uri deep://node.alpha/

init creates an identity and local configuration files in a new directory.
fetch streams the resource to stdout or saves a verified file without overwriting.
--info writes transfer details and negotiated security information to stderr.
open-uri uses config.json beside the executable and accepts exactly one URI.
Connections require TLS 1.3, X25519MLKEM768, and the server's pinned public key.
`

type serverConfig struct {
	Version     int    `json:"version"`
	Authority   string `json:"authority"`
	Listen      string `json:"listen"`
	Root        string `json:"root"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "DEEP:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, diagnostic io.Writer) error {
	if len(args) == 0 {
		_, err := io.WriteString(out, usage)
		return err
	}
	switch args[0] {
	case "help", "--help", "-h":
		_, err := io.WriteString(out, usage)
		return err
	case "version":
		if len(args) != 1 {
			return errors.New("version does not accept arguments")
		}
		fmt.Fprintf(out, "DEEP %s\n", deep.Version)
		return nil
	case "init":
		return initNode(args[1:], out, diagnostic)
	case "serve":
		return serveNode(ctx, args[1:], out, diagnostic)
	case "fetch":
		return fetchResource(ctx, args[1:], out, diagnostic)
	case "demo":
		if len(args) != 1 {
			return errors.New("demo does not accept arguments")
		}
		return demo(ctx, out)
	case "open-uri":
		return openURI(ctx, args[1:], out, diagnostic)
	default:
		return fmt.Errorf("unknown command %q; use deep --help", args[0])
	}
}

func newFlags(name string, diagnostic io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(diagnostic)
	return flags
}

func parseFlags(flags *flag.FlagSet, args []string) (bool, error) {
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return false, nil
		}
		return false, err
	}
	if flags.NArg() != 0 {
		return false, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	return true, nil
}

func initNode(args []string, out, diagnostic io.Writer) (err error) {
	flags := newFlags("deep init", diagnostic)
	authority := flags.String("authority", "", "Server identity in node.network format")
	dir := flags.String("dir", "", "New directory for identity, content, and configuration")
	address := flags.String("address", "127.0.0.1:9761", "host:port address for listening and connecting")
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
	if err = os.Mkdir(target, 0700); err != nil {
		return fmt.Errorf("create new directory (existing directories are not overwritten): %w", err)
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
	server := serverConfig{1, *authority, *address, "content", "identity.crt", "identity.key"}
	network := strings.Split(*authority, ".")[1]
	client := map[string]any{
		"version": 1,
		"networks": map[string]any{
			network: map[string]any{
				"adapter": "static",
				"endpoints": map[string]deep.Endpoint{
					*authority: {Address: *address, PinSHA256: pin, Transport: "tcp"},
				},
			},
		},
	}
	serverJSON, err := json.MarshalIndent(server, "", "  ")
	if err != nil {
		return err
	}
	clientJSON, err := json.MarshalIndent(client, "", "  ")
	if err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"identity.crt", cert, 0644},
		{"identity.key", key, 0600},
		{"server.json", append(serverJSON, '\n'), 0600},
		{"client.json", append(clientJSON, '\n'), 0644},
		{filepath.Join("content", "index.txt"), []byte("Hello from deep://" + *authority + "/\nDEEP V1: native messages and hybrid post-quantum transport.\n"), 0644},
	}
	for _, file := range files {
		if err := os.WriteFile(filepath.Join(target, file.name), file.data, file.mode); err != nil {
			return err
		}
	}
	complete = true
	fmt.Fprintf(out, "Node created: %s\nAuthority: %s\nSPKI SHA-256 pin: %s\n", target, *authority, pin)
	fmt.Fprintf(out, "Server: deep serve --config %q\nClient:  deep fetch deep://%s/ --config %q --info\n", filepath.Join(target, "server.json"), *authority, filepath.Join(target, "client.json"))
	return nil
}

func loadServerConfig(path string) (serverConfig, error) {
	var config serverConfig
	file, err := os.Open(path)
	if err != nil {
		return config, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return config, err
	}
	if stat.Size() > 65536 {
		return config, errors.New("server.json exceeds 64 KiB")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 65537))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return config, errors.New("server.json must contain exactly one JSON object")
	}
	if config.Version != 1 || config.Root == "" || config.Certificate == "" || config.PrivateKey == "" || config.Listen == "" {
		return config, errors.New("incomplete configuration or version other than 1")
	}
	if err := deep.ValidateAuthority(config.Authority); err != nil {
		return config, err
	}
	if _, _, err := net.SplitHostPort(config.Listen); err != nil {
		return config, fmt.Errorf("invalid listen address: %w", err)
	}
	base := filepath.Dir(path)
	for _, value := range []*string{&config.Root, &config.Certificate, &config.PrivateKey} {
		if !filepath.IsAbs(*value) {
			*value = filepath.Join(base, *value)
		}
	}
	return config, nil
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
	identity, err := tls.LoadX509KeyPair(config.Certificate, config.PrivateKey)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
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
	server := &deep.Server{Authority: config.Authority, TLSConfig: deep.ServerTLSConfig(identity), Handler: handler, Timeout: 30 * time.Second, MaxConnections: 128}
	fmt.Fprintf(out, "DEEP %s listening on %s for deep://%s/\nTLS 1.3 / X25519MLKEM768 / ALPN deep/1; Ctrl+C to stop.\n", deep.Version, listener.Addr(), config.Authority)
	err = server.Serve(ctx, listener)
	if ctx.Err() != nil && (err == nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed)) {
		return nil
	}
	return err
}

func fetchResource(ctx context.Context, args []string, out, diagnostic io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: deep fetch deep://node.network/path --config client.json [--output file] [--info]")
	}
	if args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(out, "Usage: deep fetch deep://node.network/path --config client.json [--output file] [--info] [--timeout 30s]")
		return nil
	}
	uri := args[0]
	if _, err := deep.ParseURI(uri); err != nil {
		return err
	}
	flags := newFlags("deep fetch", diagnostic)
	config := flags.String("config", "client.json", "Network and adapter registry")
	output := flags.String("output", "", "Save to a new file after verifying the transfer")
	info := flags.Bool("info", false, "Print metadata and negotiated security information to stderr")
	timeout := flags.Duration("timeout", 30*time.Second, "Time limit per operation")
	maxBytes := flags.Int64("max-bytes", 0, "Received size limit; 0 uses the default of 1 GiB")
	proceed, err := parseFlags(flags, args[1:])
	if err != nil || !proceed {
		return err
	}
	if *timeout <= 0 {
		return errors.New("--timeout must be positive")
	}
	if *maxBytes < 0 {
		return errors.New("--max-bytes cannot be negative")
	}
	registry, err := deep.LoadRegistry(*config)
	if err != nil {
		return err
	}
	client := deep.NewClient(registry)
	client.Timeout = *timeout
	if *maxBytes > 0 {
		client.MaxBytes = *maxBytes
	}
	var result deep.Result
	if *output == "" {
		result, err = client.Fetch(ctx, uri, out)
	} else {
		result, err = fetchFile(ctx, client, uri, *output)
	}
	if err != nil {
		return err
	}
	if *info {
		return json.NewEncoder(diagnostic).Encode(result)
	}
	return nil
}

// Keep partial transfers private. A hard link publishes the completed file
// without any overwrite race, then the temporary name is removed.
func fetchFile(ctx context.Context, client *deep.Client, uri, output string) (deep.Result, error) {
	var result deep.Result
	if _, err := os.Lstat(output); err == nil {
		return result, fmt.Errorf("output file already exists: %s", output)
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	file, err := os.CreateTemp(filepath.Dir(output), ".deep-download-*")
	if err != nil {
		return result, err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	defer file.Close()
	result, err = client.Fetch(ctx, uri, file)
	if err != nil {
		return result, err
	}
	if err := file.Sync(); err != nil {
		return result, err
	}
	if err := file.Close(); err != nil {
		return result, err
	}
	if err := os.Link(temporary, output); err != nil {
		return result, fmt.Errorf("publish file without overwriting (the destination must support hard links, such as NTFS): %w", err)
	}
	return result, nil
}

func openURI(ctx context.Context, args []string, out, diagnostic io.Writer) error {
	if len(args) != 1 {
		return errors.New("open-uri accepts exactly one URI, without options")
	}
	if _, err := deep.ParseURI(args[0]); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	err = fetchResource(ctx, []string{args[0], "--config", filepath.Join(filepath.Dir(executable), "config.json"), "--info"}, out, diagnostic)
	if err != nil {
		fmt.Fprintln(diagnostic, "DEEP:", err)
	}
	fmt.Fprintln(diagnostic, "\nPress Enter to close.")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	return err
}

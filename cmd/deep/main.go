// SPDX-License-Identifier: Apache-2.0

// deep is the reference command-line client and server for DEEP V2.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	deep "deepprotocol"
)

const usage = `DEEP V2 - an HTTP-independent resource protocol

Usage:
  deep version
  deep demo
  deep init --authority node.alpha --dir node-alpha --address 127.0.0.1:9761
  deep client-init --authority client.alpha --dir client-alpha
  deep inspect --certificate node-alpha/identity.crt
  deep serve --config node-alpha/server.json
  deep fetch deep://node.alpha/ --config node-alpha/client.json [--output file] [--info]
  deep open-uri deep://node.alpha/

init creates a private node and an authorized client in a protected new directory.
Use init --public only for a node intended to accept unauthenticated clients.
fetch streams the resource to stdout or saves a verified file without overwriting.
--info writes transfer details and negotiated security information to stderr.
open-uri uses config.json beside the executable and accepts exactly one URI.
Connections require TLS 1.3, X25519MLKEM768, and a pinned ML-DSA-65 server key.
Private nodes additionally require an authorized ML-DSA-65 client certificate.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "DEEP:", terminalText(err.Error()))
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
	case "client-init":
		return initClient(args[1:], out, diagnostic)
	case "inspect":
		return inspectCertificate(args[1:], out, diagnostic)
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
	flags.SetOutput(safeWriter{diagnostic})
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
		return false, fmt.Errorf("unexpected arguments: %q", strings.Join(flags.Args(), " "))
	}
	return true, nil
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
	if *maxBytes < 0 || *maxBytes > 1<<40 {
		return errors.New("--max-bytes must be between 0 and 1 TiB")
	}
	client, err := deep.LoadClientConfig(*config)
	if err != nil {
		return err
	}
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
		return result, fmt.Errorf("output file already exists: %q", output)
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
	err = previewURI(ctx, args[0], filepath.Join(filepath.Dir(executable), "config.json"), out, diagnostic)
	if err != nil {
		fmt.Fprintln(diagnostic, "DEEP:", terminalText(err.Error()))
	}
	fmt.Fprintln(diagnostic, "\nPress Enter to close.")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	return err
}

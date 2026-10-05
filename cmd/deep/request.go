// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	deep "deepprotocol"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// JSON on stdin keeps cookies and form values out of command-line arguments.
func requestResource(ctx context.Context, args []string, input io.Reader, out, diagnostic io.Writer) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(out, "Usage: deep request deep://node.network/ --config client.json --info < request.json")
		return nil
	}
	if len(args) == 0 {
		return errors.New("usage: deep request deep://node.network/ --config client.json --info < request.json")
	}
	uri := args[0]
	if _, err := deep.ParseURI(uri); err != nil {
		return err
	}
	flags := newFlags("deep request", diagnostic)
	config := flags.String("config", "client.json", "Network and adapter registry")
	info := flags.Bool("info", false, "Write verified response metadata to stderr")
	timeout := flags.Duration("timeout", 30*time.Second, "Time limit per operation")
	limit := flags.Int64("max-bytes", deep.MaxApplicationResponseBytes, "Response byte limit (at most 16 MiB)")
	proceed, err := parseFlags(flags, args[1:])
	if err != nil || !proceed {
		return err
	}
	if *timeout <= 0 || *limit <= 0 || *limit > deep.MaxApplicationResponseBytes {
		return errors.New("invalid timeout or response limit")
	}
	data, err := io.ReadAll(io.LimitReader(input, 2*deep.MaxApplicationRequestBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > 2*deep.MaxApplicationRequestBytes {
		return errors.New("application request JSON exceeds 2 MiB")
	}
	var inputRequest struct {
		Method  string        `json:"method"`
		Headers []deep.Header `json:"headers"`
		Body    string        `json:"body"`
	}
	if err := deep.DecodeConfigJSON(data, &inputRequest); err != nil {
		return err
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(inputRequest.Body)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != inputRequest.Body || int64(len(payload)) > deep.MaxApplicationRequestBytes {
		return errors.New("body must be canonical base64 of at most 1 MiB")
	}
	request := deep.ApplicationRequest{Method: inputRequest.Method, Headers: inputRequest.Headers, Body: payload}
	client, err := deep.LoadClientConfig(*config)
	if err != nil {
		return err
	}
	client.Timeout = *timeout
	client.MaxBytes = *limit
	var body bytes.Buffer
	result, err := client.Exchange(ctx, uri, request, &body)
	// Only an explicit rejection before upload permits a GET fallback to the
	// original read-only profile. Never retry a write, timeout or lost response.
	var remote *deep.RemoteError
	if err != nil && request.Method == "GET" && errors.As(err, &remote) && remote.Code == "UNSUPPORTED_OPERATION" {
		body.Reset()
		legacy, e := client.Fetch(ctx, uri, &body)
		err = e
		result = deep.ApplicationResult{Result: legacy, Status: 200, Headers: []deep.Header{}}
	}
	if err != nil {
		return err
	}
	if _, err = out.Write(body.Bytes()); err != nil {
		return err
	}
	if *info {
		return json.NewEncoder(diagnostic).Encode(result)
	}
	return nil
}

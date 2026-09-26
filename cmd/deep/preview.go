// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"

	deep "deepprotocol"
)

const previewLimit = 1 << 20

// terminalText preserves ordinary text and line feeds, but never allows
// terminal escape sequences, carriage-return overwrites, or bidi controls.
func terminalText(text string) string {
	var out strings.Builder
	for _, value := range text {
		if value == '\n' || (!unicode.IsControl(value) && !unicode.In(value, unicode.Cf)) {
			out.WriteRune(value)
		} else {
			quoted := strconv.QuoteRuneToASCII(value)
			out.WriteString(quoted[1 : len(quoted)-1])
		}
	}
	return out.String()
}

type safeWriter struct{ out io.Writer }

func (w safeWriter) Write(p []byte) (int, error) {
	_, err := io.WriteString(w.out, terminalText(string(p)))
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func previewURI(ctx context.Context, uri, configPath string, out, diagnostic io.Writer) error {
	client, err := deep.LoadClientConfig(configPath)
	if err != nil {
		return err
	}
	client.MaxBytes = previewLimit
	var body bytes.Buffer
	result, err := client.Fetch(ctx, uri, &body)
	if err != nil {
		return fmt.Errorf("preview is limited to 1 MiB; use deep fetch --output for larger resources: %w", err)
	}
	// Display content only after END and integrity verification succeed.
	if _, err := io.WriteString(out, terminalText(body.String())); err != nil {
		return err
	}
	return json.NewEncoder(diagnostic).Encode(result)
}

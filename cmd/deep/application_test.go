// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplicationConfigExclusiveSource(t *testing.T) {
	for _, source := range []string{
		`"root":"content","upstream":"http://127.0.0.1:5000",`,
		`"upstream":"http://example.com:5000",`,
		"",
	} {
		p := filepath.Join(t.TempDir(), "server.json")
		data := `{"version":2,"authority":"node.test","listen":"127.0.0.1:9761",` + source + `"certificate":"identity.crt","private_key":"identity.key","access_mode":"public"}`
		if err := os.WriteFile(p, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadServerConfig(p); err == nil {
			t.Fatal("invalid source accepted")
		}
	}
}
func TestRequestRejectsBadBodyEncoding(t *testing.T) {
	for _, data := range []string{
		`{"method":"POST","headers":[],"body":"!"}`,
		`{"method":"POST","headers":[],"body":[]}`,
		`{"method":"POST","headers":[],"body":"YQ==\n"}`,
		`{"method":"POST","headers":[],"body":"","body":"YQ=="}`,
	} {
		err := requestResource(context.Background(), []string{"deep://node.test/", "--config", "missing-config.json"}, strings.NewReader(data), io.Discard, io.Discard)
		if err == nil || strings.Contains(err.Error(), "missing-config") {
			t.Fatalf("invalid request reached config loading: %v", err)
		}
	}
}

// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestFileHandlerPaths(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "public")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"index.txt", "hello world.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("hello"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	handler, err := NewFileHandler(root)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	for _, path := range []string{"/", "/hello%20world.txt"} {
		resource, err := handler.Open(context.Background(), path, "")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resource.Body)
		resource.Body.Close()
		if err != nil || string(body) != "hello" {
			t.Fatalf("file: %v %q", err, body)
		}
	}
	for _, path := range []string{"/../secret", "/%2e%2e/secret", "/..%5csecret", "/index.txt:stream", "/.hidden", "//file", "/file%00", "/%ff", "/file.", "/missing"} {
		if resource, err := handler.Open(context.Background(), path, ""); err == nil {
			resource.Body.Close()
			t.Errorf("accepted unsafe/missing file %s", path)
		}
	}
	if _, err := handler.Open(context.Background(), "/", "query"); err == nil {
		t.Fatal("ignored query")
	}
	if err := os.WriteFile(filepath.Join(base, "secret"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "secret"), filepath.Join(root, "link")); err != nil {
		t.Logf("symlink test unavailable: %v", err)
		return
	}
	if resource, err := handler.Open(context.Background(), "/link", ""); err == nil {
		resource.Body.Close()
		t.Fatal("escaped root via symlink")
	}
}

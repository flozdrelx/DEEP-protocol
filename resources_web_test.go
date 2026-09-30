// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestFileHandlerWebsite(t *testing.T) {
	root := t.TempDir()
	os.Mkdir(filepath.Join(root, "docs"), 0700)
	files := map[string]string{"index.html": "<h1>Home</h1>", "index.txt": "legacy", "docs/index.html": "nested", "app.js": "window.ok=true", "style.css": "body{color:red}"}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	h, err := NewFileHandler(root)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	for _, tc := range []struct{ path, query, body, mime string }{
		{"/", "", "<h1>Home</h1>", "text/html; charset=utf-8"},
		{"/docs/", "v=1", "nested", "text/html; charset=utf-8"},
		{"/style.css", "v=3", "body{color:red}", "text/css; charset=utf-8"},
		{"/app.js", "", "window.ok=true", "text/javascript; charset=utf-8"},
	} {
		r, err := h.Open(context.Background(), tc.path, tc.query)
		if err != nil {
			t.Fatal(tc.path, err)
		}
		b, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil || string(b) != tc.body || r.MediaType != tc.mime {
			t.Fatalf("%s: %q %q %v", tc.path, b, r.MediaType, err)
		}
	}
	for _, path := range []string{"//", "/docs//", "/%2e%2e/", "/docs/../", "/.hidden/"} {
		if r, err := h.Open(context.Background(), path, ""); err == nil {
			r.Body.Close()
			t.Errorf("unsafe directory accepted: %s", path)
		}
	}
	if _, err := h.Open(context.Background(), "/", "bad%"); err == nil {
		t.Fatal("invalid query accepted")
	}
	os.Remove(filepath.Join(root, "index.html"))
	r, err := h.Open(context.Background(), "/", "")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	if string(b) != "legacy" {
		t.Fatal("text fallback lost")
	}
}

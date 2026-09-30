// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

type Resource struct {
	Body      io.ReadCloser
	MediaType string
	Size      int64
}
type Handler interface {
	Open(context.Context, string, string) (Resource, error)
}
type HandlerFunc func(context.Context, string, string) (Resource, error)

func (f HandlerFunc) Open(ctx context.Context, path, query string) (Resource, error) {
	return f(ctx, path, query)
}

type FileHandler struct{ root *os.Root }

func NewFileHandler(directory string) (*FileHandler, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	return &FileHandler{root}, nil
}
func (h *FileHandler) Close() error { return h.root.Close() }

func (h *FileHandler) Open(ctx context.Context, path, query string) (Resource, error) {
	if err := ctx.Err(); err != nil {
		return Resource{}, err
	}
	if err := ValidateResource(path, query); err != nil {
		return Resource{}, &RemoteError{"BAD_RESOURCE", "invalid resource path"}
	}
	decoded, err := url.PathUnescape(path)
	if err != nil || !utf8.ValidString(decoded) {
		return Resource{}, &RemoteError{"BAD_RESOURCE", "invalid escaped path"}
	}

	// Directory URLs use an HTML entry point when present. The text fallback
	// preserves existing DEEP nodes. Queries are cache hints for static files;
	// validation still applies, but they never participate in filesystem access.
	if strings.HasSuffix(decoded, "/") {
		resource, err := h.Open(ctx, path+"index.html", query)
		var remote *RemoteError
		if err == nil || !errors.As(err, &remote) || remote.Code != "NOT_FOUND" {
			return resource, err
		}
		return h.Open(ctx, path+"index.txt", query)
	}
	for _, part := range strings.Split(strings.TrimPrefix(decoded, "/"), "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") || strings.ContainsAny(part, "\\:*?\"<>|\x00") {
			return Resource{}, &RemoteError{"BAD_RESOURCE", "unsafe resource path"}
		}
		for _, c := range part {
			if c < 32 || c == 127 {
				return Resource{}, &RemoteError{"BAD_RESOURCE", "unsafe resource path"}
			}
		}
	}
	name := filepath.FromSlash(strings.TrimPrefix(decoded, "/"))
	// The served tree is operator-controlled. Reject observed symlinks and
	// special files; os.Root additionally prevents traversal outside the root.
	components := strings.Split(strings.TrimPrefix(decoded, "/"), "/")
	var before os.FileInfo
	for index := range components {
		if err := ctx.Err(); err != nil {
			return Resource{}, err
		}
		prefix := filepath.Join(components[:index+1]...)
		info, err := h.root.Lstat(prefix)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return Resource{}, &RemoteError{"NOT_FOUND", "resource is unavailable"}
		}
		if index < len(components)-1 && !info.IsDir() {
			return Resource{}, &RemoteError{"NOT_FOUND", "resource is unavailable"}
		}
		before = info
	}
	if before == nil || !before.Mode().IsRegular() {
		return Resource{}, &RemoteError{"NOT_FOUND", "resource is not a regular file"}
	}
	file, err := openResourceFile(h.root, name)
	if err != nil {
		return Resource{}, &RemoteError{"NOT_FOUND", "resource is unavailable"}
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) {
		file.Close()
		return Resource{}, &RemoteError{"NOT_FOUND", "resource is not a regular file"}
	}
	if info.Size() > MaxResourceSize {
		file.Close()
		return Resource{}, &RemoteError{"TOO_LARGE", "resource exceeds the protocol limit"}
	}
	if err := ctx.Err(); err != nil {
		file.Close()
		return Resource{}, err
	}

	// Use predictable browser MIME types regardless of the host's registry.
	mediaType := map[string]string{
		".html": "text/html; charset=utf-8", ".htm": "text/html; charset=utf-8",
		".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
		".mjs": "text/javascript; charset=utf-8", ".json": "application/json",
		".svg": "image/svg+xml", ".ttf": "font/ttf", ".otf": "font/otf", ".woff": "font/woff", ".woff2": "font/woff2",
	}[strings.ToLower(filepath.Ext(decoded))]
	if mediaType == "" {
		mediaType = mime.TypeByExtension(filepath.Ext(decoded))
	}
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	return Resource{file, mediaType, info.Size()}, nil
}

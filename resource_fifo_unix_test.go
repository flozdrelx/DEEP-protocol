//go:build unix

// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestFileProviderRejectsFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	handler, err := NewFileHandler(root)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	done := make(chan error, 1)
	go func() {
		resource, err := handler.Open(context.Background(), "/pipe", "")
		if resource.Body != nil {
			resource.Body.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		// Release an accidentally blocking reader so the regression cannot
		// leave a worker behind on a broken implementation.
		fd, _ := syscall.Open(filepath.Join(root, "pipe"), syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
		if fd >= 0 {
			syscall.Close(fd)
		}
		t.Fatal("FIFO open blocked")
	}
}

func TestFileProviderRejectsHiddenSymlinkAliases(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".secret"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".secret", filepath.Join(root, "public")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".private"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".private", "file"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".private", filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	handler, err := NewFileHandler(root)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	for _, path := range []string{"/public", "/alias/file"} {
		resource, err := handler.Open(context.Background(), path, "")
		if resource.Body != nil {
			resource.Body.Close()
		}
		if err == nil {
			t.Errorf("served hidden alias %s", path)
		}
	}
}

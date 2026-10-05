// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestViewerDefaultAndToggle(t *testing.T) {
	root := t.TempDir()
	settings := filepath.Join(root, "preferences", "viewer.json")
	executable := filepath.Join(root, "deep.exe")
	var output bytes.Buffer
	if err := viewerCommandAt([]string{"status", "--json"}, &output, io.Discard, executable, settings); err != nil {
		t.Fatal(err)
	}
	var state viewerState
	if err := json.Unmarshal(output.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if state.Enabled || state.Available {
		t.Fatal("viewer must be disabled without installation or opt-in")
	}
	if _, err := os.Stat(settings); !os.IsNotExist(err) {
		t.Fatal("reading defaults wrote settings")
	}
	if err := viewerCommandAt([]string{"enable"}, io.Discard, io.Discard, executable, settings); err == nil {
		t.Fatal("enabled missing viewer")
	}
	if runtime.GOOS == "windows" {
		if err := os.Mkdir(filepath.Dir(viewerPath(executable)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(viewerPath(executable), []byte("not executed"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := viewerCommandAt([]string{"enable"}, io.Discard, io.Discard, executable, settings); err != nil {
			t.Fatal(err)
		}
		preferences, err := readViewerPreferences(settings)
		if err != nil || !preferences.Enabled {
			t.Fatalf("enable: %+v %v", preferences, err)
		}
	}
	if err := viewerCommandAt([]string{"disable"}, io.Discard, io.Discard, executable, settings); err != nil {
		t.Fatal(err)
	}
	preferences, err := readViewerPreferences(settings)
	if err != nil || preferences.Enabled {
		t.Fatalf("disable: %+v %v", preferences, err)
	}
	if err := writeViewerPreferences(settings, true); err != nil {
		t.Fatal(err)
	}
	if err := writeViewerPreferences(settings, false); err != nil {
		t.Fatal("could not atomically replace preferences:", err)
	}
}
func TestViewerSettingDoesNotGateBackend(t *testing.T) {
	root := t.TempDir()
	t.Setenv("APPDATA", root)
	t.Setenv("XDG_CONFIG_HOME", root)
	// macOS ignores APPDATA and XDG_CONFIG_HOME and uses
	// $HOME/Library/Application Support. Isolate it before reading or writing.
	t.Setenv("HOME", root)
	path, err := viewerSettingsPath()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || !filepath.IsLocal(relative) {
		t.Fatalf("viewer settings escaped the temporary directory: %q (%v)", path, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected missing viewer settings, got: %v", err)
	}
	if err := requireViewerEnabled(); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected viewer disabled by default, got: %v", err)
	}
	for _, args := range [][]string{{"browse"}, {"open-uri", "deep://node.test/"}} {
		if err := run(context.Background(), args, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "disabled") {
			t.Fatalf("not blocked: %v", err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("broken preferences"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := requireViewerEnabled(); err == nil {
		t.Fatal("invalid settings enabled viewer")
	}
	var version bytes.Buffer
	if err := run(context.Background(), []string{"version"}, &version, io.Discard); err != nil {
		t.Fatal("backend read viewer preference:", err)
	}
}
func TestViewerRejectsMalformedPreferences(t *testing.T) {
	for _, value := range []string{
		`{"enabled":true}`,
		`{"version":2,"enabled":true}`,
		`{"version":1,"enabled":"true"}`,
		`{"version":1,"enabled":true,"enabled":false}`,
		`{"version":1,"enabled":null}`,
		`{"version":1,"enabled":true,"unexpected":1}`,
		strings.Repeat(" ", 4097),
	} {
		path := filepath.Join(t.TempDir(), "viewer.json")
		os.WriteFile(path, []byte(value), 0600)
		if _, err := readViewerPreferences(path); err == nil {
			t.Fatal("invalid preference accepted")
		}
	}
}

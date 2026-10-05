// SPDX-License-Identifier: Apache-2.0
package main

import (
	deep "deepprotocol"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type viewerPreferences struct {
	Version int  `json:"version"`
	Enabled bool `json:"enabled"`
}
type viewerState struct {
	Version   int    `json:"version"`
	Enabled   bool   `json:"enabled"`
	Available bool   `json:"available"`
	Settings  string `json:"settings"`
}

func viewerSettingsPath() (string, error) {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, "DEEP", "viewer.json"), nil
}
func readViewerPreferences(path string) (viewerPreferences, error) {
	value := viewerPreferences{Version: 1}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return value, nil
	}
	if err != nil {
		return value, err
	}
	if !info.Mode().IsRegular() {
		return value, errors.New("viewer settings must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return value, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return value, err
	}
	if len(data) > 4096 {
		return value, errors.New("viewer settings exceed 4 KiB")
	}
	value.Version = 0
	if err = deep.DecodeConfigJSON(data, &value); err != nil {
		return value, fmt.Errorf("invalid viewer settings: %w", err)
	}
	if value.Version != 1 {
		return value, errors.New("unsupported viewer settings version")
	}
	return value, nil
}
func writeViewerPreferences(path string, enabled bool) error {
	// Preferences contain no identity or network configuration. Publish atomically
	// so an interrupted toggle cannot leave half-written JSON.
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("viewer settings must be a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(viewerPreferences{1, enabled}, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".viewer-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err = file.Write(append(data, '\n')); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
func requireViewerEnabled() error {
	path, err := viewerSettingsPath()
	if err != nil {
		return err
	}
	value, err := readViewerPreferences(path)
	if err != nil {
		return err
	}
	if !value.Enabled {
		return errors.New("the optional viewer is disabled; use your DEEP-compatible application, or run deep viewer enable")
	}
	return nil
}
func viewerCommand(args []string, out, diagnostic io.Writer) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	path, err := viewerSettingsPath()
	if err != nil {
		return err
	}
	return viewerCommandAt(args, out, diagnostic, executable, path)
}
func viewerCommandAt(args []string, out, diagnostic io.Writer, executable, path string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	action := args[0]
	if action != "status" && action != "enable" && action != "disable" {
		return errors.New("usage: deep viewer [status|enable|disable] [--json]")
	}
	flags := newFlags("deep viewer "+action, diagnostic)
	asJSON := flags.Bool("json", false, "Print viewer state as JSON")
	proceed, err := parseFlags(flags, args[1:])
	if err != nil || !proceed {
		return err
	}
	if action == "enable" {
		if !viewerAvailable(executable) {
			return errors.New("the optional viewer is not installed; on Windows, build/copy bin/viewer first (scripts/build.ps1 -WithViewer)")
		}
		if err = writeViewerPreferences(path, true); err != nil {
			return err
		}
	}
	if action == "disable" {
		if err = writeViewerPreferences(path, false); err != nil {
			return err
		}
	}
	preferences, err := readViewerPreferences(path)
	if err != nil {
		return err
	}
	state := viewerState{1, preferences.Enabled, viewerAvailable(executable), path}
	if *asJSON {
		return json.NewEncoder(out).Encode(state)
	}
	enabled := "disabled"
	if state.Enabled {
		enabled = "enabled"
	}
	installed := "not installed"
	if state.Available {
		installed = "installed"
	}
	fmt.Fprintf(out, "Optional viewer: %s (%s).\n", enabled, installed)
	if state.Enabled {
		fmt.Fprintln(out, "Open a site with deep browse deep://node.network/ (or deep browse for the home page).")
	} else {
		fmt.Fprintln(out, "DEEP runs as a backend. Fetch, request, serve, and external applications remain available.")
	}
	fmt.Fprintln(out, "This setting does not register or replace any deep:// link handler.")
	return nil
}

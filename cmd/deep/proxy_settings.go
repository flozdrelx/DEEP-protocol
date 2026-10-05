// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	deep "deepprotocol"
)

func proxyCommand(args []string, out, diagnostic io.Writer) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	action := args[0]
	if action != "set" && action != "unset" && action != "status" {
		return errors.New("usage: deep proxy [set|unset|status] [--address IP:PORT] [--config FILE]")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	flags := newFlags("deep proxy "+action, diagnostic)
	path := flags.String("config", filepath.Join(filepath.Dir(executable), "config.json"), "DEEP client configuration")
	address := flags.String("address", "", "Native DEEP proxy IP:PORT")
	asJSON := flags.Bool("json", false, "Print proxy configuration as JSON")
	proceed, err := parseFlags(flags, args[1:])
	if err != nil || !proceed {
		return err
	}
	if action == "set" {
		if err := deep.ValidateProxyAddress(*address); err != nil {
			return err
		}
	} else if *address != "" {
		return errors.New("--address is only valid with proxy set")
	}
	state, err := configureProxy(*path, action, *address)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(out).Encode(state)
	}
	if state.Configured {
		fmt.Fprintf(out, "DEEP proxy: %s\n", state.Address)
		fmt.Fprintln(out, "Make sure the configured proxy is running before opening a deep:// link.")
	} else {
		fmt.Fprintln(out, "DEEP proxy: not configured.")
		fmt.Fprintln(out, "DEEP uses its explicitly configured direct adapters.")
	}
	return nil
}

type proxyState struct {
	Configured bool   `json:"configured"`
	Address    string `json:"address,omitempty"`
}

// A missing file may be initialized by set. Direct adapters and identity paths
// are preserved. There is no default proxy address or network-specific setting.
func configureProxy(path, action, address string) (proxyState, error) {
	state := proxyState{}
	info, statErr := os.Lstat(path)
	exists := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return state, statErr
	}
	if exists && (!info.Mode().IsRegular() || info.Size() > 1<<20) {
		return state, errors.New("DEEP configuration must be a regular file of at most 1 MiB")
	}
	config := map[string]any{"version": float64(2)}
	var before []byte
	if exists {
		var err error
		before, err = os.ReadFile(path)
		if err != nil {
			return state, err
		}
		// LoadRegistry applies the complete strict schema before editing.
		if _, err := deep.LoadRegistry(path); err != nil {
			return state, err
		}
		if err := json.Unmarshal(before, &config); err != nil {
			return state, err
		}
	}
	entry, found := config["proxy"]
	if found {
		value, valid := entry.(map[string]any)
		if !valid {
			return state, errors.New("invalid proxy configuration")
		}
		state.Address, _ = value["address"].(string)
		state.Configured = state.Address != ""
	}
	if action == "status" || (action == "unset" && !found) {
		return state, nil
	}
	if action == "unset" {
		address = ""
	}
	if state.Address == address && found {
		return state, nil
	}
	if address == "" {
		delete(config, "proxy")
	} else {
		config["proxy"] = map[string]any{"address": address}
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return state, err
	}
	data = append(data, '\n')
	// Parent directories must already exist. Configuration is explicit and never
	// writes a private identity, viewer preference, or OS/browser proxy setting.
	file, err := os.CreateTemp(filepath.Dir(path), ".deep-proxy-*.json")
	if err != nil {
		return state, err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return state, err
	}
	if err := file.Sync(); err != nil {
		return state, err
	}
	if err := file.Close(); err != nil {
		return state, err
	}
	if _, err := deep.LoadRegistry(file.Name()); err != nil {
		return state, err
	}
	now, err := os.Lstat(path)
	if exists {
		if err != nil || !os.SameFile(info, now) || !now.Mode().IsRegular() {
			return state, errors.New("configuration changed while editing; retry")
		}
		current, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, current) {
			return state, errors.New("configuration changed while editing; retry")
		}
		backup, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".proxy-backup-*")
		if err != nil {
			return state, err
		}
		_, writeErr := backup.Write(before)
		closeErr := backup.Close()
		if writeErr != nil {
			return state, writeErr
		}
		if closeErr != nil {
			return state, closeErr
		}
		if err := os.Rename(file.Name(), path); err != nil {
			return state, err
		}
	} else {
		if !errors.Is(err, os.ErrNotExist) {
			return state, errors.New("configuration appeared while editing; retry")
		}
		// Exclusive publication avoids replacing a concurrently created file.
		if err := os.Link(file.Name(), path); err != nil {
			return state, err
		}
	}
	state.Configured, state.Address = address != "", address
	return state, nil
}

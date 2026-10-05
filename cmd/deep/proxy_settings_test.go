// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	deep "deepprotocol"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGenericProxyHasNoDefaultOrNetworkSelector(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	var output bytes.Buffer
	if err := proxyCommand([]string{"status", "--config", path, "--json"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err := json.Unmarshal(output.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if len(state) != 1 || state["configured"] != false {
		t.Fatal("default proxy or network selector appeared", state)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("status created configuration")
	}
	for _, args := range [][]string{
		{"set", "--config", path},
		{"set", "--network", "alpha", "--address", "127.0.0.1:41001", "--config", path},
		{"set", "--address", "example.com:41001", "--config", path},
		{"unset", "--address", "127.0.0.1:41001", "--config", path},
	} {
		if err := proxyCommand(args, &output, &output); err == nil {
			t.Fatal("accepted missing address or unsupported option")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("invalid command created configuration")
		}
	}
}

func TestGenericProxyPreservesDirectAdaptersAndIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	original := []byte(`{"version":2,"networks":{"alpha":{"adapter":"static","endpoints":{}}},"client_identity":{"certificate":"relative.crt","private_key":"relative.key"}}`)
	os.WriteFile(path, original, 0600)
	var output bytes.Buffer
	if err := proxyCommand([]string{"set", "--address", "127.0.0.1:41001", "--config", path, "--json"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	var state proxyState
	if err := json.Unmarshal(output.Bytes(), &state); err != nil || !state.Configured || state.Address != "127.0.0.1:41001" {
		t.Fatal(state, err)
	}
	after, _ := os.ReadFile(path)
	var config map[string]any
	json.Unmarshal(after, &config)
	if config["client_identity"].(map[string]any)["private_key"] != "relative.key" || config["networks"].(map[string]any)["alpha"] == nil {
		t.Fatal("unrelated configuration lost")
	}
	if config["proxy"].(map[string]any)["address"] != state.Address {
		t.Fatal("not a generic top-level proxy")
	}
	if _, err := configureProxy(path, "unset", ""); err != nil {
		t.Fatal(err)
	}
	after, _ = os.ReadFile(path)
	var restored, before any
	json.Unmarshal(after, &restored)
	json.Unmarshal(original, &before)
	a, _ := json.Marshal(restored)
	b, _ := json.Marshal(before)
	if !bytes.Equal(a, b) {
		t.Fatal("unset did not restore direct configuration")
	}
	backups, _ := filepath.Glob(path + ".proxy-backup-*")
	if len(backups) != 2 {
		t.Fatal("backups missing")
	}
}

func TestGenericProxyWorksWithoutNetworkEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.json")
	if _, err := configureProxy(path, "set", "127.0.0.1:41001"); err != nil {
		t.Fatal(err)
	}
	if _, err := deep.LoadRegistry(path); err != nil {
		t.Fatal(err)
	}
	if _, err := configureProxy(path, "unset", ""); err != nil {
		t.Fatal(err)
	}
	client, err := deep.LoadClientConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Registry.Resolve(context.Background(), "node.alpha"); err == nil {
		t.Fatal("unset retained a route")
	}
}

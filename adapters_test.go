// SPDX-License-Identifier: Apache-2.0

package deep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var adapterTestPin = strings.Repeat("ab", 32)

func adapterTestEndpoint(port int) Endpoint {
	return Endpoint{Address: fmt.Sprintf("127.0.0.1:%d", port), PinSHA256: adapterTestPin}
}

func TestRegistryIndependentNetworks(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register("alpha", StaticAdapter{"node.alpha": adapterTestEndpoint(9761)}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register("beta", StaticAdapter{"node.beta": adapterTestEndpoint(9762)}); err != nil {
		t.Fatal(err)
	}
	for _, authority := range []string{"node.alpha", "node.beta"} {
		endpoint, err := registry.Resolve(context.Background(), authority)
		if err != nil {
			t.Fatal(err)
		}
		port := 9761
		if strings.HasSuffix(authority, ".beta") {
			port = 9762
		}
		if endpoint != adapterTestEndpoint(port) {
			t.Fatalf("%s resolved to wrong endpoint: %#v", authority, endpoint)
		}
	}
	for _, authority := range []string{"missing.alpha", "node.gamma", "node.alpha/path", "NODE.alpha"} {
		if _, err := registry.Resolve(context.Background(), authority); err == nil {
			t.Errorf("invalid or unknown authority %q resolved", authority)
		}
	}
	if err := registry.Register("alpha", StaticAdapter{}); err == nil {
		t.Fatal("duplicate registration accepted")
	}
	if err := registry.Register("UPPER", StaticAdapter{}); err == nil {
		t.Fatal("noncanonical network accepted")
	}
	if err := registry.Register("empty", nil); err == nil {
		t.Fatal("nil adapter accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := registry.Resolve(ctx, "node.alpha"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled resolution = %v", err)
	}
}

func TestRegistryConcurrentRegistrationAndResolution(t *testing.T) {
	var registry Registry // the zero value is usable
	if err := registry.Register("alpha", StaticAdapter{"node.alpha": adapterTestEndpoint(9761)}); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for index := 0; index < 40; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			network := fmt.Sprintf("net%d", index)
			if err := registry.Register(network, StaticAdapter{}); err != nil {
				t.Error(err)
			}
			for iteration := 0; iteration < 10; iteration++ {
				if _, err := registry.Resolve(context.Background(), "node.alpha"); err != nil {
					t.Error(err)
				}
			}
		}(index)
	}
	workers.Wait()
}

func TestEndpointValidation(t *testing.T) {
	for _, endpoint := range []Endpoint{
		adapterTestEndpoint(9761),
		{Address: "[::1]:9761", PinSHA256: strings.ToUpper(adapterTestPin), Transport: "tcp"},
		{Address: "localhost:1", PinSHA256: adapterTestPin, Transport: "custom-1"},
		{Address: "peer/channel-42?route=direct", PinSHA256: adapterTestPin, Transport: "custom-1"},
		{Address: "local pipe name", PinSHA256: adapterTestPin, Transport: "pipe"},
	} {
		if err := ValidateEndpoint(endpoint); err != nil {
			t.Errorf("valid endpoint %#v: %v", endpoint, err)
		}
	}
	for _, endpoint := range []Endpoint{
		{Address: "localhost", PinSHA256: adapterTestPin},
		{Address: ":9761", PinSHA256: adapterTestPin},
		{Address: "localhost:0", PinSHA256: adapterTestPin},
		{Address: "localhost:65536", PinSHA256: adapterTestPin},
		{Address: "localhost:+80", PinSHA256: adapterTestPin},
		{Address: "localhost:0080", PinSHA256: adapterTestPin},
		{Address: "local host:9761", PinSHA256: adapterTestPin},
		{Address: "http://localhost:9761", PinSHA256: adapterTestPin},
		{Address: "localhost:9761"},
		{Address: "localhost:9761", PinSHA256: strings.Repeat("z", 64)},
		{Address: "localhost:9761", PinSHA256: adapterTestPin, Transport: "Bad"},
		{Address: "localhost:9761", PinSHA256: adapterTestPin, Transport: "../tcp"},
		{Address: "", PinSHA256: adapterTestPin, Transport: "custom"},
		{Address: "peer\nchannel", PinSHA256: adapterTestPin, Transport: "custom"},
		{Address: "peer/channel", PinSHA256: adapterTestPin, Transport: "tcp"},
	} {
		if err := ValidateEndpoint(endpoint); err == nil {
			t.Errorf("invalid endpoint %#v accepted", endpoint)
		}
	}
}

func TestLoadRegistry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "networks.json")
	valid := fmt.Sprintf(`{"version":2,"networks":{"alpha":{"adapter":"static","endpoints":{"node.alpha":{"address":"127.0.0.1:9761","pin_sha256":%q}}},"beta":{"adapter":"static","endpoints":{"node.beta":{"address":"127.0.0.1:9762","pin_sha256":%q}}}}}`, adapterTestPin, adapterTestPin)
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	registry, err := LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, authority := range []string{"node.alpha", "node.beta"} {
		if _, err := registry.Resolve(context.Background(), authority); err != nil {
			t.Fatal(err)
		}
	}
	invalid := []string{
		`{}`, `null`, `[]`, `{"version":1,"networks":{}}`,
		`{"version":2,"networks":{}}`,
		`{"version":2,"version":2,"networks":{}}`,
		`{"version":2,"Version":2,"networks":{}}`,
		valid + `{}`, strings.Replace(valid, `"version":2`, `"version":2,"unknown":true`, 1),
		strings.Replace(valid, `"adapter":"static"`, `"adapter":"http"`, 1),
		strings.Replace(valid, `"node.alpha"`, `"node.beta"`, 1),
		strings.Replace(valid, `"node.alpha"`, `"NODE.alpha"`, 1),
		strings.Replace(valid, `"address":"127.0.0.1:9761"`, `"address":"127.0.0.1:9761","address":"evil:9761"`, 1),
		strings.Replace(valid, `"address":"127.0.0.1:9761"`, `"address":"127.0.0.1:9761","extra":true`, 1),
		strings.Replace(valid, `"adapter":"static"`, `"adapter":"static","command":["anything"]`, 1),
		`{"version":2,"networks":{"alpha":{"adapter":"static"}}}`,
		`{"version":2,"networks":{"alpha":{"adapter":"exec","command":[]}}}`,
		`{"version":2,"networks":{"alpha":{"adapter":"exec","command":["x"],"endpoints":{}}}}`,
		`{"version":2,"networks":{"alpha":{"adapter":"static","endpoints":{}},"alpha":{"adapter":"static","endpoints":{}}}}`,
	}
	for index, data := range invalid {
		t.Run(fmt.Sprintf("invalid-%d", index), func(t *testing.T) {
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadRegistry(path); err == nil {
				t.Fatalf("invalid config accepted: %s", data)
			}
		})
	}
}

func helperCommand(t *testing.T, mode string, args ...string) []string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := []string{executable, "-test.run=^TestExecAdapterHelper$", "--", mode}
	return append(command, args...)
}

func TestExecAdapterRoundTrip(t *testing.T) {
	t.Setenv("DEEP_ADAPTER_TEST_HELPER", "1")
	adapter := ExecAdapter{Command: helperCommand(t, "valid")}
	endpoint, err := adapter.Resolve(context.Background(), "node.alpha")
	if err != nil || endpoint != adapterTestEndpoint(9761) {
		t.Fatalf("resolve = %#v, %v", endpoint, err)
	}
	if _, err := adapter.Resolve(context.Background(), "node.alpha/private?secret"); err == nil {
		t.Fatal("resolver accepted path/query")
	}
	for _, mode := range []string{"malformed", "duplicate", "unknown", "oversize", "failure", "missing-pin"} {
		t.Run(mode, func(t *testing.T) {
			adapter := ExecAdapter{Command: helperCommand(t, mode), Timeout: 2 * time.Second}
			if _, err := adapter.Resolve(context.Background(), "node.alpha"); err == nil {
				t.Fatalf("%s resolver response accepted", mode)
			}
		})
	}
}

func TestExecAdapterTimeout(t *testing.T) {
	t.Setenv("DEEP_ADAPTER_TEST_HELPER", "1")
	adapter := ExecAdapter{Command: helperCommand(t, "timeout"), Timeout: 100 * time.Millisecond}
	started := time.Now()
	if _, err := adapter.Resolve(context.Background(), "node.alpha"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout returned %v", err)
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("resolver timeout did not terminate promptly")
	}
}

func TestAdapterOutputBufferBound(t *testing.T) {
	buffer := &limitedBuffer{limit: 32}
	if _, err := io.Copy(buffer, strings.NewReader(strings.Repeat("x", 33))); err == nil {
		t.Fatal("oversized copy was accepted")
	}
	if !buffer.exceeded || len(buffer.Bytes()) > buffer.limit {
		t.Fatal("output limit was bypassed")
	}
}

func TestLoadExecAdapterWorkingDirectory(t *testing.T) {
	t.Setenv("DEEP_ADAPTER_TEST_HELPER", "1")
	directory := t.TempDir()
	command := helperCommand(t, "cwd", directory)
	config := registryFile{Version: ProtocolVersion, Networks: map[string]networkFile{"alpha": {Adapter: "exec", Command: command}}}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "networks.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	registry, err := LoadRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Resolve(context.Background(), "node.alpha"); err != nil {
		t.Fatalf("exec adapter working directory: %v", err)
	}
}

// TestExecAdapterHelper becomes a subprocess resolver only when explicitly
// selected by the parent tests. No scripting language or shell is required.
func TestExecAdapterHelper(t *testing.T) {
	if os.Getenv("DEEP_ADAPTER_TEST_HELPER") != "1" {
		return
	}
	separator := -1
	for index, arg := range os.Args {
		if arg == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		os.Exit(2)
	}
	var request struct {
		Version   int    `json:"version"`
		Authority string `json:"authority"`
	}
	decoder := json.NewDecoder(os.Stdin)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.Version != ProtocolVersion || request.Authority != "node.alpha" {
		os.Exit(3)
	}
	switch os.Args[separator+1] {
	case "valid":
	case "cwd":
		cwd, err := os.Getwd()
		if err != nil || filepath.Clean(cwd) != filepath.Clean(os.Args[separator+2]) {
			os.Exit(4)
		}
	case "timeout":
		time.Sleep(time.Hour)
	case "malformed":
		fmt.Print("not-json")
		os.Exit(0)
	case "duplicate":
		fmt.Printf(`{"address":"127.0.0.1:9761","address":"127.0.0.1:9762","pin_sha256":%q}`, adapterTestPin)
		os.Exit(0)
	case "unknown":
		fmt.Printf(`{"address":"127.0.0.1:9761","pin_sha256":%q,"unexpected":true}`, adapterTestPin)
		os.Exit(0)
	case "missing-pin":
		fmt.Print(`{"address":"127.0.0.1:9761"}`)
		os.Exit(0)
	case "oversize":
		fmt.Print(strings.Repeat("x", maxAdapterOutput+1))
		os.Exit(0)
	case "failure":
		os.Exit(7)
	default:
		os.Exit(5)
	}
	if err := json.NewEncoder(os.Stdout).Encode(adapterTestEndpoint(9761)); err != nil {
		os.Exit(6)
	}
	os.Exit(0)
}

func TestConfigJSONRejectsAmbiguousValues(t *testing.T) {
	type nested struct {
		Name string `json:"name"`
	}
	type config struct {
		Name   string   `json:"name"`
		Nested *nested  `json:"nested,omitempty"`
		Args   []string `json:"args,omitempty"`
	}
	for _, input := range []string{
		`{"name":"valid"}`, `{"name":"valid","nested":{"name":"child"},"args":["","\ud83d\ude00"]}`,
	} {
		var result config
		if err := DecodeConfigJSON([]byte(input), &result); err != nil {
			t.Fatalf("valid input: %v", err)
		}
	}
	for _, input := range []string{
		`null`, `[]`, `{}`, `{"Name":"wrong case"}`, `{"name":"x","NAME":"y"}`,
		`{"name":"x","name":"y"}`, `{"name":"x","extra":true}`, `{"name":null}`,
		`{"name":"x","nested":null}`, `{"name":"x","nested":{}}`,
		`{"name":"x","args":[null]}`, `{"name":"x","args":[123]}`,
		`{"name":"\ud800"}`, `{"name":"\udfff"}`, `{"name":"x"}{}`,
		"{\"name\":\"\xff\"}",
	} {
		var result config
		if err := DecodeConfigJSON([]byte(input), &result); err == nil {
			t.Fatalf("accepted invalid JSON: %q", input)
		}
	}
}

func TestClientIdentityConfiguration(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "client.json")
	cert, key, _, err := GenerateClientIdentity("client.alpha", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{"client.crt": cert, "client.key": key} {
		if err := os.WriteFile(filepath.Join(directory, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	config := fmt.Sprintf(`{"version":2,"networks":{"alpha":{"adapter":"static","endpoints":{"node.alpha":{"address":"127.0.0.1:9761","pin_sha256":%q}}}},"client_identity":{"certificate":"client.crt","private_key":"client.key"}}`, adapterTestPin)
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := LoadClientConfig(path)
	if err != nil || client.Identity == nil {
		t.Fatalf("client identity: %v", err)
	}
	if err := ValidateClientIdentity(*client.Identity); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Registry.Resolve(context.Background(), "node.alpha"); err != nil {
		t.Fatal(err)
	}
	for _, identity := range []string{`null`, `{}`, `{"certificate":"client.crt"}`, `{"certificate":"","private_key":"client.key"}`, `{"certificate":"client.crt","private_key":null}`, `{"certificate":"client.crt","private_key":"secret\n.key"}`, `{"certificate":"client.crt","private_key":"secret\u202e.key"}`} {
		bad := config[:strings.Index(config, `"client_identity":`)] + `"client_identity":` + identity + `}`
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadRegistry(path); err == nil {
			t.Fatalf("accepted invalid identity %s", identity)
		}
	}
	missing := strings.Replace(config, `"client.key"`, `"missing.key"`, 1)
	if err := os.WriteFile(path, []byte(missing), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRegistry(path); err != nil {
		t.Fatalf("registry should only validate identity shape: %v", err)
	}
	if _, err := LoadClientConfig(path); err == nil {
		t.Fatal("missing private key accepted")
	} else if strings.Contains(err.Error(), "missing.key") || strings.Contains(err.Error(), directory) {
		t.Fatal("private identity path leaked into diagnostic")
	}
	serverCert, serverKey, _, err := GenerateIdentity("node.alpha", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "client.crt"), serverCert, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "client.key"), serverKey, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClientConfig(path); err == nil {
		t.Fatal("server identity accepted for client role")
	}
}

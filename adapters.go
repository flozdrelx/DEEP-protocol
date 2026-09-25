// SPDX-License-Identifier: Apache-2.0

package deep

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Endpoint binds an address to the exact server public key expected by a
// network adapter. PinSHA256 is the lowercase or uppercase hex SHA-256 digest
// of the DER-encoded SubjectPublicKeyInfo (SPKI). An empty Transport means tcp.
// For tcp, Address is host:port. Other transports interpret Address as an
// opaque printable ASCII string; their registered dialer validates its meaning.
type Endpoint struct {
	Address   string `json:"address"`
	PinSHA256 string `json:"pin_sha256"`
	Transport string `json:"transport,omitempty"`
}

// ValidateEndpoint checks endpoint syntax, without performing DNS lookups.
func ValidateEndpoint(endpoint Endpoint) error {
	if len(endpoint.Address) < 1 || len(endpoint.Address) > 1024 {
		return fmt.Errorf("endpoint address must contain 1 to 1024 bytes")
	}
	if endpoint.Transport != "" && !validTransportName(endpoint.Transport) {
		return fmt.Errorf("invalid endpoint transport name")
	}
	for index := 0; index < len(endpoint.Address); index++ {
		if endpoint.Address[index] < ' ' || endpoint.Address[index] >= 0x7f {
			return fmt.Errorf("endpoint address must contain printable ASCII characters")
		}
	}
	if endpoint.Transport == "" || endpoint.Transport == "tcp" {
		host, portText, err := net.SplitHostPort(endpoint.Address)
		if err != nil || host == "" {
			return fmt.Errorf("TCP endpoint address must be host:port")
		}
		if err := validateASCII(endpoint.Address); err != nil || strings.ContainsAny(host, "/\\?#@") {
			return fmt.Errorf("invalid endpoint host")
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText {
			return fmt.Errorf("endpoint port must be an integer from 1 to 65535")
		}
	}
	if len(endpoint.PinSHA256) != 64 {
		return fmt.Errorf("endpoint pin_sha256 must contain 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(endpoint.PinSHA256); err != nil {
		return fmt.Errorf("endpoint pin_sha256 must contain 64 hexadecimal characters")
	}
	return nil
}

func validTransportName(name string) bool {
	if len(name) < 1 || len(name) > 32 || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for index := 1; index < len(name); index++ {
		if !isLowerAlnum(name[index]) && name[index] != '-' {
			return false
		}
	}
	return true
}

// NetworkAdapter resolves a canonical authority to an authenticated endpoint.
// Paths, queries and fragments are never disclosed to a resolver.
type NetworkAdapter interface {
	Resolve(context.Context, string) (Endpoint, error)
}

// Registry routes authorities to explicitly installed network adapters. Its
// registration and lookup operations are safe for concurrent use.
type Registry struct {
	mu       sync.RWMutex
	networks map[string]NetworkAdapter
}

func NewRegistry() *Registry {
	return &Registry{networks: make(map[string]NetworkAdapter)}
}

func (registry *Registry) Register(network string, adapter NetworkAdapter) error {
	if !validLabel(network) {
		return fmt.Errorf("network must be a canonical lowercase ASCII label")
	}
	if adapter == nil {
		return fmt.Errorf("network adapter must not be nil")
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.networks == nil {
		registry.networks = make(map[string]NetworkAdapter)
	}
	if _, exists := registry.networks[network]; exists {
		return fmt.Errorf("network %q is already registered", network)
	}
	registry.networks[network] = adapter
	return nil
}

func (registry *Registry) Resolve(ctx context.Context, authority string) (Endpoint, error) {
	if err := ValidateAuthority(authority); err != nil {
		return Endpoint{}, err
	}
	if err := ctx.Err(); err != nil {
		return Endpoint{}, err
	}
	network := authority[strings.LastIndexByte(authority, '.')+1:]
	registry.mu.RLock()
	adapter, exists := registry.networks[network]
	registry.mu.RUnlock()
	if !exists {
		return Endpoint{}, fmt.Errorf("no adapter installed for network %q", network)
	}
	endpoint, err := adapter.Resolve(ctx, authority)
	if err != nil {
		return Endpoint{}, fmt.Errorf("resolve %s: %w", authority, err)
	}
	if err := ctx.Err(); err != nil {
		return Endpoint{}, err
	}
	if err := ValidateEndpoint(endpoint); err != nil {
		return Endpoint{}, fmt.Errorf("adapter returned an invalid endpoint: %w", err)
	}
	return endpoint, nil
}

// StaticAdapter is an explicitly trusted local name-to-endpoint mapping. The
// map must not be modified while it is used for resolution.
type StaticAdapter map[string]Endpoint

func (adapter StaticAdapter) Resolve(ctx context.Context, authority string) (Endpoint, error) {
	if err := ctx.Err(); err != nil {
		return Endpoint{}, err
	}
	if err := ValidateAuthority(authority); err != nil {
		return Endpoint{}, err
	}
	endpoint, exists := adapter[authority]
	if !exists {
		return Endpoint{}, fmt.Errorf("unknown authority %q", authority)
	}
	return endpoint, ValidateEndpoint(endpoint)
}

const maxAdapterOutput = 64 * 1024

// ExecAdapter invokes an explicitly configured local resolver executable,
// without a shell. A request is one JSON object on stdin; stdout must contain
// exactly one Endpoint JSON object. Resolver configuration is trusted code.
type ExecAdapter struct {
	Command []string
	Timeout time.Duration
	workDir string
}

func (adapter ExecAdapter) Resolve(ctx context.Context, authority string) (Endpoint, error) {
	if err := ValidateAuthority(authority); err != nil {
		return Endpoint{}, err
	}
	if len(adapter.Command) == 0 || strings.TrimSpace(adapter.Command[0]) == "" {
		return Endpoint{}, fmt.Errorf("exec adapter requires a command")
	}
	timeout := adapter.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	if timeout < 0 {
		return Endpoint{}, fmt.Errorf("exec adapter timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	request, err := json.Marshal(struct {
		Version   int    `json:"version"`
		Authority string `json:"authority"`
	}{Version: 1, Authority: authority})
	if err != nil {
		return Endpoint{}, err
	}
	commandName := adapter.Command[0]
	if adapter.workDir != "" && !filepath.IsAbs(commandName) && strings.ContainsAny(commandName, `/\`) {
		commandName = filepath.Join(adapter.workDir, commandName)
	}
	command := exec.CommandContext(ctx, commandName, adapter.Command[1:]...)
	command.Dir = adapter.workDir
	command.Stdin = bytes.NewReader(append(request, '\n'))
	command.WaitDelay = 250 * time.Millisecond
	stdout := &limitedBuffer{limit: maxAdapterOutput}
	stderr := &limitedBuffer{limit: 4096}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return Endpoint{}, fmt.Errorf("exec adapter: %w", ctx.Err())
		}
		if stdout.exceeded {
			return Endpoint{}, fmt.Errorf("exec adapter output exceeds %d bytes", maxAdapterOutput)
		}
		return Endpoint{}, fmt.Errorf("exec adapter failed: %w", err)
	}
	if stdout.exceeded {
		return Endpoint{}, fmt.Errorf("exec adapter output exceeds %d bytes", maxAdapterOutput)
	}
	var endpoint Endpoint
	if err := decodeAdapterJSON(stdout.Bytes(), &endpoint); err != nil {
		return Endpoint{}, fmt.Errorf("invalid exec adapter response: %w", err)
	}
	if err := ValidateEndpoint(endpoint); err != nil {
		return Endpoint{}, fmt.Errorf("invalid exec adapter response: %w", err)
	}
	return endpoint, nil
}

type limitedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (buffer *limitedBuffer) Write(data []byte) (int, error) {
	if len(data) > buffer.limit-buffer.buffer.Len() {
		buffer.exceeded = true
		return 0, fmt.Errorf("output limit exceeded")
	}
	return buffer.buffer.Write(data)
}

func (buffer *limitedBuffer) Bytes() []byte {
	return buffer.buffer.Bytes()
}

type registryFile struct {
	Version  int                    `json:"version"`
	Networks map[string]networkFile `json:"networks"`
}

type networkFile struct {
	Adapter   string              `json:"adapter"`
	Endpoints map[string]Endpoint `json:"endpoints,omitempty"`
	Command   []string            `json:"command,omitempty"`
}

// LoadRegistry loads a strict version-1 adapter configuration. Relative resolver
// paths and the resolver working directory are based on the configuration file.
func LoadRegistry(path string) (*Registry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	const maxConfigSize = 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(file, maxConfigSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigSize {
		return nil, fmt.Errorf("adapter configuration exceeds 1 MiB")
	}
	var config registryFile
	if err := decodeAdapterJSON(data, &config); err != nil {
		return nil, fmt.Errorf("invalid adapter configuration: %w", err)
	}
	if config.Version != 1 {
		return nil, fmt.Errorf("adapter configuration version must be 1")
	}
	if len(config.Networks) == 0 {
		return nil, fmt.Errorf("adapter configuration requires at least one network")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	registry := NewRegistry()
	for network, config := range config.Networks {
		var adapter NetworkAdapter
		switch config.Adapter {
		case "static":
			if config.Endpoints == nil || config.Command != nil {
				return nil, fmt.Errorf("static network %q requires endpoints and forbids command", network)
			}
			for authority, endpoint := range config.Endpoints {
				if err := ValidateAuthority(authority); err != nil || !strings.HasSuffix(authority, "."+network) {
					return nil, fmt.Errorf("endpoint %q does not belong to network %q", authority, network)
				}
				if err := ValidateEndpoint(endpoint); err != nil {
					return nil, fmt.Errorf("endpoint %q: %w", authority, err)
				}
			}
			adapter = StaticAdapter(config.Endpoints)
		case "exec":
			if len(config.Command) == 0 || strings.TrimSpace(config.Command[0]) == "" || config.Endpoints != nil {
				return nil, fmt.Errorf("exec network %q requires command and forbids endpoints", network)
			}
			adapter = ExecAdapter{Command: config.Command, workDir: filepath.Dir(absolutePath)}
		default:
			return nil, fmt.Errorf("unsupported adapter %q for network %q", config.Adapter, network)
		}
		if err := registry.Register(network, adapter); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

// JSON duplicate keys are errors, including differently cased spellings which
// encoding/json would otherwise map to the same struct field.
func decodeAdapterJSON(data []byte, target any) error {
	tokens := json.NewDecoder(bytes.NewReader(data))
	if err := checkAdapterJSONValue(tokens, 0); err != nil {
		return err
	}
	if _, err := tokens.Token(); err != io.EOF {
		return fmt.Errorf("expected exactly one JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func checkAdapterJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("JSON nesting exceeds 64 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]bool)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key must be a string")
			}
			canonicalKey := strings.ToLower(key)
			if keys[canonicalKey] {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			keys[canonicalKey] = true
			if err := checkAdapterJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := checkAdapterJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}

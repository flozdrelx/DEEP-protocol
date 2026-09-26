// SPDX-License-Identifier: Apache-2.0

package deep

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
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
	}{Version: ProtocolVersion, Authority: authority})
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
	Version        int                    `json:"version"`
	Networks       map[string]networkFile `json:"networks"`
	ClientIdentity *clientIdentityFile    `json:"client_identity,omitempty"`
}

type clientIdentityFile struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

type networkFile struct {
	Adapter   string              `json:"adapter"`
	Endpoints map[string]Endpoint `json:"endpoints,omitempty"`
	Command   []string            `json:"command,omitempty"`
}

// LoadRegistry loads a strict version-2 adapter configuration. Optional client
// identity paths are validated, but their files are loaded only by LoadClientConfig.
// Resolver paths and working directories are relative to the configuration file.
func LoadRegistry(path string) (*Registry, error) {
	config, directory, err := loadRegistryConfig(path)
	if err != nil {
		return nil, err
	}
	return registryFromConfig(config, directory)
}

// LoadClientConfig loads trusted resolution settings and an optional TLS client
// identity. Identity material is never passed to an executable resolver.
func LoadClientConfig(path string) (*Client, error) {
	config, directory, err := loadRegistryConfig(path)
	if err != nil {
		return nil, err
	}
	registry, err := registryFromConfig(config, directory)
	if err != nil {
		return nil, err
	}
	client := NewClient(registry)
	if config.ClientIdentity != nil {
		resolve := func(value string) string {
			if filepath.IsAbs(value) {
				return value
			}
			return filepath.Join(directory, value)
		}
		identity, err := tls.LoadX509KeyPair(resolve(config.ClientIdentity.Certificate), resolve(config.ClientIdentity.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("could not load client certificate/private key; check the configured files and matching key pair")
		}
		if err := ValidateClientIdentity(identity); err != nil {
			return nil, fmt.Errorf("invalid client identity: %w", err)
		}
		client.Identity = &identity
	}
	return client, nil
}

func loadRegistryConfig(path string) (registryFile, string, error) {
	var config registryFile
	file, err := os.Open(path)
	if err != nil {
		return config, "", err
	}
	defer file.Close()
	const maxConfigSize = 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(file, maxConfigSize+1))
	if err != nil {
		return config, "", err
	}
	if len(data) > maxConfigSize {
		return config, "", fmt.Errorf("adapter configuration exceeds 1 MiB")
	}
	if err := DecodeConfigJSON(data, &config); err != nil {
		return config, "", fmt.Errorf("invalid adapter configuration: %w", err)
	}
	if config.Version != ProtocolVersion {
		return config, "", fmt.Errorf("adapter configuration version must be %d", ProtocolVersion)
	}
	if len(config.Networks) == 0 {
		return config, "", fmt.Errorf("adapter configuration requires at least one network")
	}
	if identity := config.ClientIdentity; identity != nil {
		if !validIdentityPath(identity.Certificate) || !validIdentityPath(identity.PrivateKey) {
			return config, "", fmt.Errorf("client_identity requires certificate and private_key paths")
		}
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return config, "", err
	}
	return config, filepath.Dir(absolutePath), nil
}

func validIdentityPath(value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	for _, c := range value {
		if unicode.IsControl(c) || unicode.In(c, unicode.Cf, unicode.Zl, unicode.Zp) {
			return false
		}
	}
	return true
}

func registryFromConfig(config registryFile, directory string) (*Registry, error) {
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
			adapter = ExecAdapter{Command: config.Command, workDir: directory}
		default:
			return nil, fmt.Errorf("unsupported adapter %q for network %q", config.Adapter, network)
		}
		if err := registry.Register(network, adapter); err != nil {
			return nil, err
		}
	}
	return registry, nil
}

// DecodeConfigJSON decodes one bounded UTF-8 JSON object into a plain Go
// configuration struct. Struct field names are exact and case-sensitive; every
// exported field is required unless tagged omitempty. Unknown fields, duplicate
// keys, nulls (including array elements), and malformed Unicode are rejected.
func DecodeConfigJSON(data []byte, target any) error {
	if len(data) > 1024*1024 || !utf8.Valid(data) {
		return fmt.Errorf("configuration exceeds 1 MiB or contains invalid UTF-8")
	}
	if err := validateSurrogates(data); err != nil {
		return fmt.Errorf("invalid configuration Unicode: %w", err)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) < 2 || trimmed[0] != '{' {
		return fmt.Errorf("expected exactly one JSON object")
	}
	tokens := json.NewDecoder(bytes.NewReader(data))
	tokens.UseNumber()
	if err := checkAdapterJSONValue(tokens, 0); err != nil {
		return err
	}
	if _, err := tokens.Token(); err != io.EOF {
		return fmt.Errorf("expected exactly one JSON object")
	}
	targetType := reflect.TypeOf(target)
	if targetType == nil || targetType.Kind() != reflect.Pointer || reflect.ValueOf(target).IsNil() {
		return fmt.Errorf("configuration destination must be a non-nil pointer")
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	if err := checkConfigShape(value, targetType.Elem()); err != nil {
		return err
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func decodeAdapterJSON(data []byte, target any) error {
	return DecodeConfigJSON(data, target)
}

func checkConfigShape(value any, target reflect.Type) error {
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	switch target.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("expected configuration object")
		}
		known := make(map[string]reflect.StructField)
		for i := 0; i < target.NumField(); i++ {
			field := target.Field(i)
			if !field.IsExported() {
				continue
			}
			tag := strings.Split(field.Tag.Get("json"), ",")
			name := tag[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			known[name] = field
			optional := false
			for _, option := range tag[1:] {
				if option == "omitempty" {
					optional = true
				}
			}
			if _, exists := object[name]; !exists && !optional {
				return fmt.Errorf("missing configuration field %q", name)
			}
		}
		for name, child := range object {
			field, exists := known[name]
			if !exists {
				return fmt.Errorf("unknown configuration field %q", name)
			}
			if err := checkConfigShape(child, field.Type); err != nil {
				return fmt.Errorf("field %q: %w", name, err)
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("expected configuration map")
		}
		for key, child := range object {
			if err := checkConfigShape(child, target.Elem()); err != nil {
				return fmt.Errorf("key %q: %w", key, err)
			}
		}
	case reflect.Slice, reflect.Array:
		array, ok := value.([]any)
		if !ok {
			return fmt.Errorf("expected configuration array")
		}
		for _, child := range array {
			if err := checkConfigShape(child, target.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkAdapterJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("JSON nesting exceeds 64 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return fmt.Errorf("null configuration values are forbidden")
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	var closing json.Delim
	switch delimiter {
	case '{':
		closing = '}'
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
			if keys[key] {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			keys[key] = true
			if err := checkAdapterJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		closing = ']'
		for decoder.More() {
			if err := checkAdapterJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	end, err := decoder.Token()
	if err != nil {
		return err
	}
	if end != closing {
		return fmt.Errorf("invalid JSON container")
	}
	return nil
}

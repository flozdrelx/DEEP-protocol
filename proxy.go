// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Proxy/1 is a local native TCP control handshake followed by opaque DEEP TLS.
// It is independent of HTTP, SOCKS and any particular overlay network.
const ProxyMagic = "DPRX0001"
const MaxProxyMessage = 4096
const ProxyTransport = "deep-proxy"

type ProxyRequest struct {
	Version   int    `json:"version"`
	Operation string `json:"operation"`
	Authority string `json:"authority"`
	PinSHA256 string `json:"pin_sha256,omitempty"`
}
type ProxyResponse struct {
	Version   int    `json:"version"`
	OK        bool   `json:"ok"`
	PinSHA256 string `json:"pin_sha256,omitempty"`
	Error     string `json:"error,omitempty"`
}

// WriteProxyMessage writes one bounded control frame, including its preface.
func WriteProxyMessage(w io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > MaxProxyMessage {
		return errors.New("proxy message exceeds 4096 bytes")
	}
	header := make([]byte, 12)
	copy(header, ProxyMagic)
	binary.BigEndian.PutUint32(header[8:], uint32(len(data)))
	if err := writeAll(w, header); err != nil {
		return err
	}
	return writeAll(w, data)
}

// ReadProxyMessage consumes exactly one frame, leaving subsequent TLS bytes intact.
func ReadProxyMessage(r io.Reader, value any) error {
	var header [12]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[8:])
	if string(header[:8]) != ProxyMagic || size == 0 || size > MaxProxyMessage {
		return errors.New("invalid native DEEP proxy frame")
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(r, data); err != nil {
		return err
	}
	return DecodeConfigJSON(data, value)
}

// ValidateProxyAddress accepts literal loopback IPs only, with no DNS lookups.
// A local proxy is explicitly trusted to authenticate its network's identity pins.
func ValidateProxyAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("DEEP proxy must be a numeric loopback IP:PORT")
	}
	ip := net.ParseIP(host)
	number, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
		return errors.New("DEEP proxy must be a numeric loopback IP and port from 1 to 65535")
	}
	return nil
}

type ProxyAdapter struct {
	Address string
	Timeout time.Duration
}

func (adapter ProxyAdapter) Resolve(ctx context.Context, authority string) (Endpoint, error) {
	if adapter.Address == "" {
		return Endpoint{}, errors.New("DEEP proxy is not configured; use deep proxy set --address IP:PORT")
	}
	if err := ValidateAuthority(authority); err != nil {
		return Endpoint{}, err
	}
	connection, response, err := proxyHandshake(ctx, adapter.Address, adapter.Timeout,
		ProxyRequest{Version: 1, Operation: "resolve", Authority: authority})
	if err != nil {
		return Endpoint{}, err
	}
	_ = connection.Close()
	return Endpoint{Address: proxyEndpointAddress(adapter.Address, authority), PinSHA256: response.PinSHA256, Transport: ProxyTransport}, nil
}

func proxyEndpointAddress(address, authority string) string {
	return (&url.URL{Scheme: ProxyTransport, Host: address, Path: "/" + authority}).String()
}

func parseProxyEndpoint(endpoint Endpoint) (string, string, error) {
	if err := ValidateEndpoint(endpoint); err != nil {
		return "", "", err
	}
	u, err := url.Parse(endpoint.Address)
	if err != nil || endpoint.Transport != ProxyTransport || u.Scheme != ProxyTransport ||
		u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" {
		return "", "", errors.New("invalid native DEEP proxy endpoint")
	}
	if err := ValidateProxyAddress(u.Host); err != nil {
		return "", "", err
	}
	authority := strings.TrimPrefix(u.Path, "/")
	if err := ValidateAuthority(authority); err != nil {
		return "", "", err
	}
	if endpoint.Address != proxyEndpointAddress(u.Host, authority) {
		return "", "", errors.New("noncanonical proxy endpoint")
	}
	return u.Host, authority, nil
}

// DialProxy opens a stream through a proxy. The caller still performs DEEP TLS
// and verifies the server key; the proxy cannot substitute an unpinned peer.
func DialProxy(ctx context.Context, endpoint Endpoint) (net.Conn, error) {
	address, authority, err := parseProxyEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	connection, _, err := proxyHandshake(ctx, address, 0, ProxyRequest{
		Version: 1, Operation: "connect", Authority: authority, PinSHA256: strings.ToLower(endpoint.PinSHA256),
	})
	return connection, err
}

func proxyHandshake(ctx context.Context, address string, timeout time.Duration, request ProxyRequest) (net.Conn, ProxyResponse, error) {
	var response ProxyResponse
	if err := ValidateProxyAddress(address); err != nil {
		return nil, response, err
	}
	if timeout < 0 {
		return nil, response, errors.New("proxy timeout must be positive")
	}
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, response, fmt.Errorf("DEEP proxy unavailable at %s; check that the configured proxy is running: %w", address, err)
	}
	success := false
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer func() {
		stop()
		if !success {
			_ = connection.Close()
		}
	}()
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, response, err
	}
	if err := WriteProxyMessage(connection, request); err != nil {
		return nil, response, err
	}
	if err := ReadProxyMessage(connection, &response); err != nil {
		return nil, response, fmt.Errorf("invalid DEEP proxy response: %w", err)
	}
	if response.Version != 1 {
		return nil, response, errors.New("unsupported DEEP proxy version")
	}
	if !response.OK {
		// Do not reflect arbitrary text from an untrusted local listener.
		return nil, response, errors.New("DEEP proxy rejected the requested authority or identity pin")
	}
	pin, err := hex.DecodeString(response.PinSHA256)
	if err != nil || len(pin) != 32 || len(response.PinSHA256) != 64 || response.Error != "" {
		return nil, response, errors.New("DEEP proxy returned an invalid identity pin")
	}
	if request.Operation == "connect" && !strings.EqualFold(request.PinSHA256, response.PinSHA256) {
		return nil, response, errors.New("DEEP proxy identity pin changed during connection")
	}
	if !stop() || ctx.Err() != nil {
		return nil, response, ctx.Err()
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return nil, response, err
	}
	success = true
	return connection, response, nil
}

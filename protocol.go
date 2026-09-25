// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

const Version = "1.0.0"
const HeaderSize = 20
const MaxMetadataSize = 8192
const MaxChunkSize = 65536
const MaxResourceSize int64 = 1 << 40

type MessageType uint8

const (
	Hello MessageType = iota + 1
	Welcome
	Request
	Response
	Data
	End
	Error
	Close
)

var ErrProtocol = errors.New("DEEP protocol error")

type Frame struct {
	Type      MessageType
	RequestID uint32
	Metadata  json.RawMessage
	Body      []byte
}

func protocolError(message string) error { return fmt.Errorf("%w: %s", ErrProtocol, message) }

func validateHeader(kind MessageType, id, metaSize, bodySize uint32) error {
	if kind < Hello || kind > Close {
		return protocolError("unknown message type")
	}
	if metaSize < 2 || metaSize > MaxMetadataSize || bodySize > MaxChunkSize {
		return protocolError("frame size limit exceeded")
	}
	if kind != Data && bodySize != 0 {
		return protocolError("only DATA has a body")
	}
	if kind == Data && bodySize == 0 {
		return protocolError("empty DATA frame")
	}
	if (kind == Hello || kind == Welcome || kind == Close) && id != 0 {
		return protocolError("control message with request ID")
	}
	if kind >= Request && kind <= End && id == 0 {
		return protocolError("resource message without request ID")
	}
	return nil
}

// ReadFrame is independent of sockets, TLS, and network adapters.
func ReadFrame(reader io.Reader) (Frame, error) {
	var frame Frame
	var header [HeaderSize]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return frame, err
	}
	if string(header[:4]) != "DEEP" || header[4] != 1 || binary.BigEndian.Uint16(header[6:8]) != 0 {
		return frame, protocolError("unknown magic, framing version, or flags")
	}
	frame.Type = MessageType(header[5])
	frame.RequestID = binary.BigEndian.Uint32(header[8:12])
	metaSize, bodySize := binary.BigEndian.Uint32(header[12:16]), binary.BigEndian.Uint32(header[16:20])
	if err := validateHeader(frame.Type, frame.RequestID, metaSize, bodySize); err != nil {
		return frame, err
	}
	frame.Metadata = make([]byte, metaSize)
	if _, err := io.ReadFull(reader, frame.Metadata); err != nil {
		return frame, err
	}
	if err := validateJSON(frame.Metadata); err != nil {
		return frame, err
	}
	frame.Body = make([]byte, bodySize)
	if _, err := io.ReadFull(reader, frame.Body); err != nil {
		return frame, err
	}
	return frame, nil
}

func WriteFrame(writer io.Writer, frame Frame) error {
	if len(frame.Metadata) > MaxMetadataSize || len(frame.Body) > MaxChunkSize {
		return protocolError("frame size limit exceeded")
	}
	if err := validateHeader(frame.Type, frame.RequestID, uint32(len(frame.Metadata)), uint32(len(frame.Body))); err != nil {
		return err
	}
	if err := validateJSON(frame.Metadata); err != nil {
		return err
	}
	var header [HeaderSize]byte
	copy(header[:4], "DEEP")
	header[4], header[5] = 1, byte(frame.Type)
	binary.BigEndian.PutUint32(header[8:12], frame.RequestID)
	binary.BigEndian.PutUint32(header[12:16], uint32(len(frame.Metadata)))
	binary.BigEndian.PutUint32(header[16:20], uint32(len(frame.Body)))
	for _, part := range [][]byte{header[:], frame.Metadata, frame.Body} {
		if err := writeAll(writer, part); err != nil {
			return err
		}
	}
	return nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func send(writer io.Writer, kind MessageType, id uint32, metadata any, body []byte) error {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	return WriteFrame(writer, Frame{kind, id, raw, body})
}

// DecodeMetadata rejects missing, unknown, and null fields as well as invalid types.
func DecodeMetadata(frame Frame, destination any, fields ...string) error {
	if err := validateJSON(frame.Metadata); err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(frame.Metadata, &object); err != nil {
		return err
	}
	if len(object) != len(fields) {
		return protocolError("missing or unknown metadata fields")
	}
	for _, name := range fields {
		value, ok := object[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return protocolError("missing or null metadata field: " + name)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(frame.Metadata))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return protocolError("invalid metadata types: " + err.Error())
	}
	return nil
}

func validateJSON(raw []byte) error {
	if len(raw) < 2 || len(raw) > MaxMetadataSize || !utf8.Valid(raw) {
		return protocolError("invalid metadata encoding or size")
	}
	if err := validateSurrogates(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return protocolError("metadata must be a JSON object")
	}
	if err := walkJSON(decoder, first, 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return protocolError("trailing JSON data")
	}
	return nil
}

func walkJSON(decoder *json.Decoder, token json.Token, depth int) error {
	delim, container := token.(json.Delim)
	if !container {
		return nil
	}
	if depth > 16 {
		return protocolError("metadata nesting exceeds 16")
	}
	switch delim {
	case '{':
		keys := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return protocolError("invalid JSON")
			}
			key, ok := keyToken.(string)
			if !ok || keys[key] {
				return protocolError("duplicate or invalid metadata key")
			}
			keys[key] = true
			value, err := decoder.Token()
			if err != nil {
				return protocolError("invalid JSON")
			}
			if err := walkJSON(decoder, value, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return protocolError("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return protocolError("invalid JSON")
			}
			if err := walkJSON(decoder, value, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return protocolError("invalid JSON array")
		}
	default:
		return protocolError("unexpected JSON delimiter")
	}
	return nil
}

// encoding/json replaces unpaired surrogates; reject those before decoding.
func validateSurrogates(raw []byte) error {
	quoted := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return protocolError("unfinished JSON escape")
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return protocolError("short Unicode escape")
		}
		value, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return protocolError("invalid Unicode escape")
		}
		i += 4
		if value >= 0xDC00 && value <= 0xDFFF {
			return protocolError("unpaired Unicode surrogate")
		}
		if value >= 0xD800 && value <= 0xDBFF {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return protocolError("unpaired Unicode surrogate")
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xDC00 || low > 0xDFFF {
				return protocolError("unpaired Unicode surrogate")
			}
			i += 6
		}
	}
	return nil
}

type helloMetadata struct {
	Versions []int `json:"versions"`
}
type welcomeMetadata struct {
	Version  int `json:"version"`
	MaxChunk int `json:"max_chunk"`
}
type requestMetadata struct {
	Authority string `json:"authority"`
	Path      string `json:"path"`
	Query     string `json:"query"`
	Operation string `json:"operation"`
}
type responseMetadata struct {
	MediaType string `json:"media_type"`
	Size      int64  `json:"size"`
}
type endMetadata struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type RemoteError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *RemoteError) Error() string { return e.Code + ": " + e.Message }

func validateMediaType(value string) bool {
	if len(value) == 0 || len(value) > 255 {
		return false
	}
	for _, b := range []byte(value) {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}

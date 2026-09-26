// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestHelloVector(t *testing.T) {
	want, _ := hex.DecodeString("44454550020100000000000000000010000000007b2276657273696f6e73223a5b325d7d")
	var encoded bytes.Buffer
	if err := send(&encoded, Hello, 0, helloMetadata{[]int{ProtocolVersion}}, nil); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded.Bytes(), want) {
		t.Fatalf("vector mismatch: %x", encoded.Bytes())
	}
	frame, err := ReadFrame(bytes.NewReader(want))
	if err != nil {
		t.Fatal(err)
	}
	var hello helloMetadata
	if err := DecodeMetadata(frame, &hello, "versions"); err != nil || len(hello.Versions) != 1 || hello.Versions[0] != ProtocolVersion {
		t.Fatalf("decode: %v %+v", err, hello)
	}
}

type byteReader struct{ reader io.Reader }

func (b byteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return b.reader.Read(p)
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return w.Buffer.Write(p)
}

func TestFragmentationCoalescingAndShortWrites(t *testing.T) {
	var writer shortWriter
	data := bytes.Repeat([]byte{0, 1, 2, 255}, 100)
	for _, id := range []uint32{1, 2} {
		if err := send(&writer, Data, id, struct{}{}, data); err != nil {
			t.Fatal(err)
		}
	}
	reader := byteReader{bytes.NewReader(writer.Bytes())}
	for _, id := range []uint32{1, 2} {
		frame, err := ReadFrame(reader)
		if err != nil {
			t.Fatal(err)
		}
		if frame.RequestID != id || frame.Type != Data || !bytes.Equal(frame.Body, data) {
			t.Fatal("lost frame boundary or bytes")
		}
	}
}

func rawFrame(kind MessageType, id uint32, meta, body []byte) []byte {
	raw := make([]byte, HeaderSize+len(meta)+len(body))
	copy(raw, "DEEP")
	raw[4] = ProtocolVersion
	raw[5] = byte(kind)
	binary.BigEndian.PutUint32(raw[8:12], id)
	binary.BigEndian.PutUint32(raw[12:16], uint32(len(meta)))
	binary.BigEndian.PutUint32(raw[16:20], uint32(len(body)))
	copy(raw[20:], meta)
	copy(raw[20+len(meta):], body)
	return raw
}

func TestHeaderValidation(t *testing.T) {
	valid := rawFrame(Hello, 0, []byte(`{"versions":[2]}`), nil)
	cases := []struct {
		name   string
		offset int
		value  byte
	}{{"magic", 0, 'X'}, {"version", 4, 1}, {"flags", 7, 1}, {"type", 5, 255}}
	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			raw := bytes.Clone(valid)
			raw[testcase.offset] = testcase.value
			if _, err := ReadFrame(bytes.NewReader(raw)); err == nil {
				t.Fatal("accepted invalid header")
			}
		})
	}
	for _, raw := range [][]byte{rawFrame(Hello, 1, []byte(`{}`), nil), rawFrame(Request, 0, []byte(`{}`), nil),
		rawFrame(Hello, 0, []byte(`{}`), []byte("body")), rawFrame(Data, 1, []byte(`{}`), nil)} {
		if _, err := ReadFrame(bytes.NewReader(raw)); err == nil {
			t.Fatal("accepted invalid control/body state")
		}
	}
	for _, field := range []struct {
		offset int
		size   uint32
	}{{12, MaxMetadataSize + 1}, {16, MaxChunkSize + 1}} {
		raw := bytes.Clone(valid[:HeaderSize])
		binary.BigEndian.PutUint32(raw[field.offset:field.offset+4], field.size)
		if _, err := ReadFrame(bytes.NewReader(raw)); !errors.Is(err, ErrProtocol) {
			t.Fatalf("must reject length before reading payload: %v", err)
		}
	}
}

func TestStrictJSONAndRequiredFields(t *testing.T) {
	bad := []string{`[]`, `null`, `{"x":1,"x":2}`, `{"x":NaN}`, `{"x":"\ud800"}`, `{"x":"\udfff"}`, `{"x":"\ud800\u0000"}`, `{} {}`, `{"x":` + strings.Repeat("[", 17) + `0` + strings.Repeat("]", 17) + `}`}
	for _, metadata := range bad {
		if _, err := ReadFrame(bytes.NewReader(rawFrame(Hello, 0, []byte(metadata), nil))); err == nil {
			t.Fatalf("accepted %s", metadata)
		}
	}
	for _, metadata := range []string{`{"version":1,"extra":1}`, `{"version":null}`, `{}`, `{"Version":1}`, `{"version":true}`} {
		var value struct {
			Version int `json:"version"`
		}
		if err := DecodeMetadata(Frame{Metadata: []byte(metadata)}, &value, "version"); err == nil {
			t.Fatalf("accepted fields %s", metadata)
		}
	}
	for _, metadata := range []string{`{"x":"\ud83d\ude00"}`, `{"x":"[\"\\u]"}`} {
		if err := validateJSON([]byte(metadata)); err != nil {
			t.Fatalf("rejected valid string %s: %v", metadata, err)
		}
	}
	if err := validateJSON([]byte{'{', '"', 'x', '"', ':', '"', 255, '"', '}'}); err == nil {
		t.Fatal("accepted invalid UTF-8")
	}
}

func TestEveryTruncatedFrameFails(t *testing.T) {
	raw := rawFrame(Data, 1, []byte(`{}`), []byte("payload"))
	for length := 0; length < len(raw); length++ {
		if _, err := ReadFrame(bytes.NewReader(raw[:length])); err == nil {
			t.Fatalf("accepted truncation %d", length)
		}
	}
}

func FuzzReadFrame(f *testing.F) {
	f.Add(rawFrame(Hello, 0, []byte(`{"versions":[2]}`), nil))
	f.Add(rawFrame(Data, 7, []byte(`{}`), []byte("test")))
	f.Fuzz(func(t *testing.T, raw []byte) {
		frame, err := ReadFrame(bytes.NewReader(raw))
		if err != nil {
			return
		}
		var encoded bytes.Buffer
		if err := WriteFrame(&encoded, frame); err != nil {
			t.Fatal(err)
		}
		roundtrip, err := ReadFrame(&encoded)
		if err != nil {
			t.Fatal(err)
		}
		if frame.Type != roundtrip.Type || frame.RequestID != roundtrip.RequestID || !bytes.Equal(frame.Body, roundtrip.Body) {
			t.Fatal("roundtrip changed frame")
		}
	})
}

func TestRemoteErrorTextLimits(t *testing.T) {
	for _, remote := range []*RemoteError{
		{"NOT_FOUND", "resource unavailable"},
		{"A_2", ""},
		{"INTERNAL_ERROR", strings.Repeat("\u00e9", 512)},
	} {
		if err := ValidateRemoteError(remote); err != nil {
			t.Fatal(err)
		}
		if remote.Error() != remote.Code+": "+remote.Message {
			t.Fatal("valid message changed")
		}
	}
	for _, remote := range []*RemoteError{
		nil, {"", "empty"}, {"not_found", "lowercase"}, {"2BAD", "leading digit"},
		{strings.Repeat("A", 65), "long code"}, {"BAD\x1b", "escape"},
		{"BAD", strings.Repeat("\u00e9", 513)}, {"BAD", "\xff"},
		{"BAD", "line\nbreak"}, {"BAD", "\x1b[2J"}, {"BAD", "\u0085"},
		{"BAD", "\u202e"}, {"BAD", "\u2028"}, {"BAD", "\u2029"},
	} {
		if ValidateRemoteError(remote) == nil {
			t.Fatal("accepted invalid remote error")
		}
		if remote.Error() != "invalid remote error" {
			t.Fatal("unsafe error leaked")
		}
	}
}

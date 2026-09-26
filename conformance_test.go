// SPDX-License-Identifier: Apache-2.0
package deep

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestIndependentFrameVectors(t *testing.T) {
	data, err := os.ReadFile("interop/frame_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var suite struct {
		ProtocolVersion int `json:"protocol_version"`
		Vectors         []struct {
			Name      string          `json:"name"`
			Hex       string          `json:"hex"`
			Valid     bool            `json:"valid"`
			Type      MessageType     `json:"type"`
			RequestID uint32          `json:"request_id"`
			Metadata  json.RawMessage `json:"metadata"`
			BodyHex   string          `json:"body_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &suite); err != nil {
		t.Fatal(err)
	}
	if suite.ProtocolVersion != ProtocolVersion || len(suite.Vectors) < 20 {
		t.Fatal("invalid conformance suite")
	}
	for _, vector := range suite.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(vector.Hex)
			if err != nil {
				t.Fatal(err)
			}
			reader := bytes.NewReader(raw)
			frame, err := ReadFrame(byteReader{reader})
			if !vector.Valid {
				if err == nil {
					t.Fatal("accepted invalid vector")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if reader.Len() != 0 || frame.Type != vector.Type || frame.RequestID != vector.RequestID || hex.EncodeToString(frame.Body) != vector.BodyHex {
				t.Fatal("decoded frame differs")
			}
			var got, want any
			if err := json.Unmarshal(frame.Metadata, &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(vector.Metadata, &want); err != nil {
				t.Fatal(err)
			}
			gotJSON, _ := json.Marshal(got)
			wantJSON, _ := json.Marshal(want)
			if !bytes.Equal(gotJSON, wantJSON) {
				t.Fatal("decoded metadata differs")
			}
			var encoded bytes.Buffer
			if err := WriteFrame(&encoded, frame); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded.Bytes(), raw) {
				t.Fatal("wire bytes changed on round trip")
			}
		})
	}
}

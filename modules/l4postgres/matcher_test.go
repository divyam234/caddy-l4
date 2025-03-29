// l4postgres_test.go
package l4postgres

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mholt/caddy-l4/layer4"
)

func buildStartupMessage(version uint32, params map[string]string) []byte {
	var payload bytes.Buffer

	// Write protocol version
	binary.Write(&payload, binary.BigEndian, version)

	// Write parameters (key\0value\0)
	// Iterate deterministically for consistent test data (optional but good practice)
	// For this test, map iteration order doesn't matter for correctness, but might for debugging.
	for k, v := range params {
		payload.WriteString(k)
		payload.WriteByte(0) // Null terminator for key
		payload.WriteString(v)
		payload.WriteByte(0) // Null terminator for value
	}

	// Write final null terminator for the parameter list
	payload.WriteByte(0)

	payloadBytes := payload.Bytes()
	payloadLen := len(payloadBytes)
	totalLen := uint32(payloadLen + initMessageSizeLength) // Add 4 bytes for the length field itself

	var message bytes.Buffer
	binary.Write(&message, binary.BigEndian, totalLen) // Write total length header
	message.Write(payloadBytes)                        // Write the payload

	return message.Bytes()
}

func buildSSLRequest() []byte {
	var message bytes.Buffer
	totalLen := uint32(8) // 4 bytes length, 4 bytes code
	payloadCode := uint32(sslRequestCode)

	binary.Write(&message, binary.BigEndian, totalLen)    // Message Length (8)
	binary.Write(&message, binary.BigEndian, payloadCode) // SSLRequest Code

	return message.Bytes()
}

func TestMatchPostgres(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantMatch bool
		wantErr   bool
	}{
		{
			name:      "Valid SSLRequest",
			input:     buildSSLRequest(),
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "Valid StartupMessage V3 (No Params)",
			input:     buildStartupMessage(0x00030000, nil), // Protocol 3.0
			wantMatch: true,
			wantErr:   false,
		},
		{
			name: "Valid StartupMessage V3 (With Params)",
			input: buildStartupMessage(0x00030000, map[string]string{
				"user":     "testuser",
				"database": "testdb",
			}),
			wantMatch: true,
			wantErr:   false,
		},
		{
			name: "Valid StartupMessage V3 (One Param)",
			input: buildStartupMessage(0x00030000, map[string]string{
				"client_encoding": "UTF8",
			}),
			wantMatch: true,
			wantErr:   false,
		},

		// --- Non-Matches (Malformed Postgres or Other Protocols) ---
		{
			name:      "Too Short (EOF reading length)",
			input:     []byte{0x00, 0x00}, // Only 2 bytes, less than length header size
			wantMatch: false,
			wantErr:   false, // Should return false, nil for insufficient initial data
		},
		{
			name:      "Invalid Message Length (Too Small)",
			input:     []byte{0x00, 0x00, 0x00, 0x07}, // Length 7, minimum is 8
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "Zero Payload Length (Invalid)",
			input:     []byte{0x00, 0x00, 0x00, 0x04}, // Length 4 -> Payload 0
			wantMatch: false,
			wantErr:   false,
		},
		{
			name: "Too Short (EOF reading payload)",
			// Declares length 10, but only provides 8 bytes total (4 length + 4 payload)
			input:     append([]byte{0x00, 0x00, 0x00, 0x0A}, buildStartupMessage(0x00030000, nil)[4:8]...),
			wantMatch: false,
			wantErr:   false, // Returns false, nil for incomplete message based on header
		},
		{
			name: "Unsupported Protocol Version (V2)",
			input: buildStartupMessage(0x00020000, map[string]string{ // Protocol 2.0
				"user": "test",
			}),
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "SSLRequest Code but Wrong Length",
			input:     append(buildSSLRequest()[:4], []byte{0x01, 0x02, 0x03, 0x04, 0x05}...), // Length OK, Code OK, Payload != 4 bytes
			wantMatch: false,                                                                  // Strict check fails
			wantErr:   false,
		},
		{
			name: "StartupMessage Payload Too Short",
			// Length 8 -> Payload 4. Needs >= 5 for V3 (Version + Terminator)
			input:     []byte{0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name: "Malformed Startup (Missing Final Null)",
			// Build valid message, then remove the last byte (the final null terminator)
			input: func() []byte {
				msg := buildStartupMessage(0x00030000, map[string]string{"user": "test"})
				return msg[:len(msg)-1]
			}(),
			wantMatch: false,
			wantErr:   false,
		},
		{
			name: "Malformed Startup (Missing Value Null)",
			input: func() []byte {
				// Construct manually: Len, Ver, "user\0", "test" (NO NULL) , final \0
				payload := []byte{
					0x00, 0x03, 0x00, 0x00, // Version
					'u', 's', 'e', 'r', 0x00, // Key + Null
					't', 'e', 's', 't', // Value (Missing Null!)
					0x00, // Final Null
				}
				totalLen := uint32(len(payload) + initMessageSizeLength)
				header := make([]byte, 4)
				binary.BigEndian.PutUint32(header, totalLen)
				return append(header, payload...)
			}(),
			wantMatch: false,
			wantErr:   false,
		},
		{
			name: "Malformed Startup (Missing Key Null)",
			input: func() []byte {
				// Construct manually: Len, Ver, "user" (NO NULL), "test\0", final \0
				payload := []byte{
					0x00, 0x03, 0x00, 0x00, // Version
					'u', 's', 'e', 'r', // Key (Missing Null!)
					't', 'e', 's', 't', 0x00, // Value + Null
					0x00, // Final Null
				}
				totalLen := uint32(len(payload) + initMessageSizeLength)
				header := make([]byte, 4)
				binary.BigEndian.PutUint32(header, totalLen)
				return append(header, payload...)
			}(),
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "Other Protocol (HTTP GET)",
			input:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "Other Protocol (SSH)",
			input:     []byte("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"),
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "Other Protocol (Random Bytes)",
			input:     []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE},
			wantMatch: false,
			wantErr:   false,
		},
		{
			name: "Declared Payload Too Large",
			input: func() []byte {
				largePayloadLen := uint32(maxStartupPayloadSize + 1)
				totalLen := largePayloadLen + initMessageSizeLength
				header := make([]byte, 4)
				binary.BigEndian.PutUint32(header, totalLen)
				return header
			}(),
			wantMatch: false,
			wantErr:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reader := bytes.NewReader(tc.input)
			cx := layer4.Connection{
				Conn: mockConn{reader},
			}

			m := &MatchPostgres{}

			match, err := m.Match(&cx)
			if tc.wantErr {
				if err == nil {
					t.Errorf("Match() expected an error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Match() unexpected error: %v", err)
				}
			}

			if match != tc.wantMatch {
				t.Errorf("Match() got match = %v, want %v", match, tc.wantMatch)
			}
		})
	}
}

type mockConn struct {
	io.Reader
}

func (m mockConn) Read(p []byte) (int, error)         { return m.Reader.Read(p) }
func (m mockConn) Close() error                       { return nil }
func (m mockConn) LocalAddr() net.Addr                { return nil }
func (m mockConn) RemoteAddr() net.Addr               { return nil }
func (m mockConn) SetDeadline(t time.Time) error      { return nil }
func (m mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m mockConn) SetWriteDeadline(t time.Time) error { return nil }
func (m mockConn) Write(p []byte) (int, error)        { return len(p), nil }

var _ net.Conn = (*mockConn)(nil)

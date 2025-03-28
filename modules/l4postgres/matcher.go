// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package l4postgres allows the L4 multiplexing of Postgres connections
package l4postgres

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"

	"github.com/mholt/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&MatchPostgres{})
}

const (
	sslRequestCode = 80877103
	// byte size of the message length field
	initMessageSizeLength = 4
	// Smallest possible valid message length: SSLRequest (4 len + 4 code = 8)
	// or StartupMessage v3 (4 len + 4 version + 1 null terminator = 9)
	minMessageLength = 8 // Keep 8 as SSLRequest is shortest valid message
	// Smallest valid StartupMessage v3 payload: protocol version (4) + terminator null (1) = 5
	minStartupPayloadLength = 5 // protocol version (4) + final null byte (1)
	// Maximum reasonable size for a startup message payload (e.g., 16 KiB).
	maxStartupPayloadSize = 16 * 1024
)

// message provides readers for various types and updates the offset.
// It tracks internal errors to avoid cascading failures on bad data.
type message struct {
	data                      []byte
	offset                    uint32
	err                       error // Track errors during reads
	lastReadStringStartOffset uint32 // Track where the last ReadString started
}

// ReadUint32 reads a big-endian uint32 from the current offset.
// It updates the offset and records any error (e.g., reading past buffer).
func (b *message) ReadUint32() (r uint32) {
	if b.err != nil {
		return 0 // Don't proceed if already errored
	}
	if b.offset+4 > uint32(len(b.data)) {
		b.err = fmt.Errorf("readUint32: %w", io.ErrUnexpectedEOF) // Mark error: not enough data
		return 0
	}
	r = binary.BigEndian.Uint32(b.data[b.offset : b.offset+4])
	b.offset += 4
	return r
}

// ReadString reads a null-terminated string from the current offset.
// It updates the offset past the null terminator and records any error
// (e.g., reading past buffer, missing null terminator).
func (b *message) ReadString() (r string) {
	if b.err != nil {
		return "" // Don't proceed if already errored
	}
	b.lastReadStringStartOffset = b.offset // Record start position
	start := b.offset
	maximum := uint32(len(b.data))

	// Check if we are already at or past the end
	if start >= maximum {
		// Trying to read a string when no bytes are left.
		// If start == maximum, technically a null byte *could* be considered there,
		// resulting in an empty string. Let's treat reading from exact end as empty string
		// but reading past end as error. Postgres protocol often ends with null byte pairs.
		if start == maximum {
			// Allow reading empty string if we are exactly at the end
			// This handles cases like the final null terminator for parameters.
			b.err = nil // Ensure no prior error blocks this.
			return ""
		}
		// This case (start > maximum) should be impossible if offset logic is correct.
		b.err = fmt.Errorf("readString: offset %d past buffer length %d", start, maximum)
		return ""
	}

	end := b.offset
	// Find null terminator within bounds
	for ; end < maximum && b.data[end] != 0; end++ {
	}

	// Check if null terminator was found within bounds
	if end == maximum {
		// Reached end of data without finding null terminator
		b.err = errors.New("readString: missing null terminator")
		// Return what we found up to the end, but mark error
		r = string(b.data[start:maximum])
		b.offset = maximum
		return r
	}

	// Null terminator found at 'end' (b.data[end] == 0)
	r = string(b.data[start:end])
	b.offset = end + 1 // Move offset past the null terminator
	return r
}

// NewMessageFromBytes wraps the raw bytes of a message to enable processing
func newMessageFromBytes(b []byte) *message {
	return &message{data: b}
}

// MatchPostgres is able to match Postgres connections.
type MatchPostgres struct{}

// CaddyModule returns the Caddy module information.
func (*MatchPostgres) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.postgres",
		New: func() caddy.Module { return new(MatchPostgres) },
	}
}

// Match returns true if the connection looks like the Postgres protocol.
// It returns (false, nil) if the connection does not match Postgres startup.
// It returns (false, err) only if an I/O error occurs before matching could be determined.
func (m *MatchPostgres) Match(cx *layer4.Connection) (bool, error) {
	// 1. Read Message Length Header
	head := make([]byte, initMessageSizeLength)
	// Use ReadFull to ensure we get exactly initMessageSizeLength bytes
	n, err := io.ReadFull(cx, head)
	if err != nil {
		// If EOF or UnexpectedEOF happens reading the very first few bytes,
		// it's definitely not a valid Postgres startup. Return false, nil.
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// Not enough data even for the length header, cannot be Postgres startup
			return false, nil
		}
		// For other read errors at this stage, return the error.
		return false, fmt.Errorf("reading message length header: %w", err)
	}
	// This check is technically redundant with io.ReadFull guaranteeing the read amount
	// unless initMessageSizeLength is 0, but kept for safety.
	if n < initMessageSizeLength {
		return false, nil // Should not happen with ReadFull if no error
	}

	// 2. Parse and Validate Message Length
	messageLen := binary.BigEndian.Uint32(head)
	if messageLen < minMessageLength {
		// Message length is too small to contain SSLRequest code or ProtocolVersion + terminator
		// Note: messageLen includes the 4 bytes for the length itself.
		return false, nil // Doesn't match minimum valid Postgres message length
	}

	// Calculate payload length (message data excluding the length field itself)
	payloadLen := messageLen - initMessageSizeLength

	// Check against maximum allowed size to prevent DoS via large allocation claim
	if payloadLen > maxStartupPayloadSize {
		// Declared size is too large, treat as non-matching to avoid large allocation
		return false, nil
	}

	// 3. Read the Message Payload
	// Avoid allocation if payload is zero (although minMessageLength check mostly prevents this)
	if payloadLen == 0 {
         // A payload length of 0 is invalid for both SSLRequest (needs code)
         // and StartupMessage v3+ (needs version+terminator).
         return false, nil
	}
	data := make([]byte, payloadLen)
	n, err = io.ReadFull(cx, data)
	if err != nil {
		// If EOF/UnexpectedEOF occurs here, the client sent a length
		// but didn't send enough data. This is not a valid/complete Postgres message.
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil // Incomplete message based on header length
		}
		// Other I/O errors reading the payload
		return false, fmt.Errorf("reading message payload (declared length %d): %w", payloadLen, err)
	}
	// Redundant check due to io.ReadFull, kept for safety.
	if n < int(payloadLen) {
		return false, nil // Should not happen with ReadFull if no error
	}

	// 4. Parse the Payload using the message helper
	b := newMessageFromBytes(data)
	code := b.ReadUint32() // Read first 4 bytes (SSL Code or Protocol Version)
	if b.err != nil {
		// Error reading the first 4 bytes of the payload (e.g., payloadLen was < 4).
		// The minMessageLength check should prevent payloadLen < 4, but handle defensively.
		return false, nil // Malformed message (too short payload)
	}

	// 5. Check for SSLRequest
	// A valid SSLRequest has the specific code and a payload consisting *only* of that code.
	if code == sslRequestCode && payloadLen == 4 {
		// Correct SSLRequest detected
		return true, nil
	}
	// If the code matches SSLRequest but payload length is wrong, it's technically malformed.
	// For a matcher, we could be lenient, but let's be strict: only match exact SSLRequest format.
	// if code == sslRequestCode { return true, nil } // <-- More lenient version

	// 6. Check for StartupMessage V3+
	// If it wasn't SSLRequest, the 'code' is the ProtocolVersion
	protocolVersion := code
	if majorVersion := protocolVersion >> 16; majorVersion < 3 {
		// Unsupported protocol version (e.g., v2). Not a match for modern Postgres.
		return false, nil
	}

	// Check minimum payload size required for StartupMessage (version + kv pairs + terminator)
	if payloadLen < minStartupPayloadLength {
		// Payload must be at least 5 bytes (4 for version, 1 for final null).
		return false, nil // Too short for a valid v3 startup message structure
	}

	// At this point, it has a valid-looking length, a V3+ protocol version.
	// Now, we need to verify the parameter structure minimally.
	// We expect key-value pairs (null-terminated strings) followed by a single null byte terminator.

	for {
		// Check for parsing errors *before* attempting reads in the loop
		if b.err != nil {
			return false, nil // Error occurred in previous read (e.g., missing null)
		}

		// Check if we are at the end *before* reading the key.
		// This handles the case where the last read was the value of the final parameter.
		if b.offset == uint32(len(b.data)) {
             // We should have encountered the final null terminator byte *before* reaching the exact end.
             // Reaching the end here means the message was truncated or missing the final null.
			return false, nil // Malformed: Missing final null terminator
		}

		// Try reading parameter key
		_ = b.ReadString() // We don't need the key value, just check structure & advance offset
		if b.err != nil {
			// Error reading key (e.g., truncated message, missing null)
			return false, nil // Malformed parameter structure
		}

		// Check if the *last string read* was the empty string "" signifying the terminator.
		// This happens if ReadString was called when b.offset pointed directly at a null byte.
		// Check: Was the start offset the byte right before the current offset? AND Was that byte null?
		if (b.offset > 0) && (b.offset-1 == b.lastReadStringStartOffset) && (b.data[b.offset-1] == 0) {
			// This confirms the last ReadString just consumed a single null byte. This is the terminator.
			// Now, check if this terminator is exactly at the end of the payload.
			if b.offset == uint32(len(b.data)) {
				// Correctly terminated StartupMessage found.
				return true, nil
			} else {
				// Found terminator byte, but there's extra data after it. Malformed.
				return false, nil
			}
		}

		// If it wasn't the terminator, we expect a value string.
		// Check again for errors or reaching end prematurely *before* reading value.
        if b.err != nil {
            return false, nil // Error from reading key
        }
		if b.offset >= uint32(len(b.data)) {
			// Reached end of buffer after reading a key, but expected a value or terminator. Malformed.
			return false, nil
		}

		// Try reading the value string
		_ = b.ReadString() // We don't need the value, just check structure & advance offset
		if b.err != nil {
			// Error reading value (e.g., truncated message, missing null)
			return false, nil // Malformed parameter structure
		}

	}
}

// UnmarshalCaddyfile sets up the MatchPostgres from Caddyfile tokens. Syntax:
//
//	postgres
func (m *MatchPostgres) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val() // consume wrapper name
	if d.CountRemainingArgs() > 0 {
		return d.ArgErr()
	}
	if d.NextBlock(d.Nesting()) {
		return d.Errf("malformed layer4 connection matcher '%s': blocks are not supported", wrapper)
	}
	return nil
}

// Interface guards
var (
	_ layer4.ConnMatcher    = (*MatchPostgres)(nil)
	_ caddyfile.Unmarshaler = (*MatchPostgres)(nil)
)
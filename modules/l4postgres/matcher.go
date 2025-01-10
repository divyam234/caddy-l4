package l4postgres

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/divyam234/caddy-l4/layer4"
)

func init() {
	caddy.RegisterModule(&MatchPostgres{})
}

const (
	sslRequestCode        = 80877103
	initMessageSizeLength = 4
)

// Buffer pool for the header
var headerPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, initMessageSizeLength)
		return &buf
	},
}

type message struct {
	data   []byte
	offset uint32
}

func (b *message) ReadUint32() (r uint32) {
	r = binary.BigEndian.Uint32(b.data[b.offset : b.offset+4])
	b.offset += 4
	return r
}

func (b *message) ReadString() (r string) {
	end := b.offset
	maximum := uint32(len(b.data))
	for ; end != maximum && b.data[end] != 0; end++ {
	}
	r = string(b.data[b.offset:end])
	b.offset = end + 1
	return r
}

type startupMessage struct {
	ProtocolVersion uint32
	Parameters      map[string]string
}

type MatchPostgres struct{}

func (*MatchPostgres) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.postgres",
		New: func() caddy.Module { return new(MatchPostgres) },
	}
}

func (m *MatchPostgres) Match(cx *layer4.Connection) (bool, error) {
	// Get header buffer from pool
	headerPtr := headerPool.Get().(*[]byte)
	header := *headerPtr
	if _, err := io.ReadFull(cx, header); err != nil {
		headerPool.Put(headerPtr)
		return false, err
	}
	messageLength := binary.BigEndian.Uint32(header) - initMessageSizeLength
	headerPool.Put(headerPtr)

	// Allocate data buffer for this message
	data := make([]byte, messageLength)
	if _, err := io.ReadFull(cx, data); err != nil {
		return false, err
	}

	b := &message{data: data}

	code := b.ReadUint32()
	if code == sslRequestCode {
		return true, nil
	}

	if majorVersion := code >> 16; majorVersion < 3 {
		return false, errors.New("pg protocol < 3.0 is not supported")
	}

	startup := &startupMessage{
		ProtocolVersion: code,
		Parameters:      make(map[string]string),
	}

	for {
		k := b.ReadString()
		if k == "" {
			break
		}
		startup.Parameters[k] = b.ReadString()
	}

	return len(startup.Parameters) > 0, nil
}

func (m *MatchPostgres) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	_, wrapper := d.Next(), d.Val()

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

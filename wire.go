package main

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

// Minimal protobuf wire primitives — just the field shapes the Devin
// GetChatMessage wire uses (varint / LDN / fixed64 / fixed32). Field numbers
// verified against the Devin Desktop 3.10.27 embedded descriptors
// (pi-devin docs/protocol-audit-2026-09-29).

func appendVarint(dst []byte, v uint64) []byte {
	for v > 127 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func tagBytes(field, wire int) []byte {
	return appendVarint(nil, uint64(field<<3|wire))
}

func vField(field int, v uint64) []byte {
	out := tagBytes(field, 0)
	return appendVarint(out, v)
}

func sField(field int, s string) []byte {
	out := tagBytes(field, 2)
	out = appendVarint(out, uint64(len(s)))
	return append(out, s...)
}

func mField(field int, body []byte) []byte {
	out := tagBytes(field, 2)
	out = appendVarint(out, uint64(len(body)))
	return append(out, body...)
}

func f64Field(field int, x float64) []byte {
	out := tagBytes(field, 1)
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], math.Float64bits(x))
	return append(out, b[:]...)
}

// ---- decode ----

type protoField struct {
	num  int
	wire int
	v    uint64 // wire 0
	b    []byte // wire 1/2/5
}

func readVarint(buf []byte, i int) (uint64, int, error) {
	var res uint64
	var shift uint
	for {
		if i >= len(buf) {
			return 0, i, io.ErrUnexpectedEOF
		}
		b := buf[i]
		i++
		res |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return res, i, nil
		}
		shift += 7
		if shift >= 70 {
			return 0, i, fmt.Errorf("oversized varint")
		}
	}
}

func iterFields(buf []byte) ([]protoField, error) {
	var out []protoField
	i := 0
	for i < len(buf) {
		tag, next, err := readVarint(buf, i)
		if err != nil {
			return nil, err
		}
		i = next
		num := int(tag >> 3)
		wire := int(tag & 7)
		if num < 1 || num > 0x1fffffff {
			return nil, fmt.Errorf("invalid protobuf tag %d", tag)
		}
		switch wire {
		case 0:
			v, after, err := readVarint(buf, i)
			if err != nil {
				return nil, err
			}
			i = after
			out = append(out, protoField{num: num, wire: wire, v: v})
		case 1:
			if i+8 > len(buf) {
				return nil, fmt.Errorf("truncated fixed64")
			}
			out = append(out, protoField{num: num, wire: wire, b: buf[i : i+8]})
			i += 8
		case 2:
			n, after, err := readVarint(buf, i)
			if err != nil {
				return nil, err
			}
			i = after
			if i+int(n) > len(buf) {
				return nil, fmt.Errorf("truncated protobuf field %d", num)
			}
			out = append(out, protoField{num: num, wire: wire, b: buf[i : i+int(n)]})
			i += int(n)
		case 5:
			if i+4 > len(buf) {
				return nil, fmt.Errorf("truncated fixed32")
			}
			out = append(out, protoField{num: num, wire: wire, b: buf[i : i+4]})
			i += 4
		default:
			return nil, fmt.Errorf("unsupported protobuf wire type %d", wire)
		}
	}
	return out, nil
}

// ---- Connect-RPC stream framing ----
// Frame = [flags:1][len:uint32 BE][payload]. flag 0x01 = gzip, 0x02 = EOS
// trailer (JSON). Verified byte-exact in pi-devin/src/wire.ts.

const maxConnectFrame = 64 << 20

func frameConnectStream(body []byte, compress bool) ([]byte, error) {
	payload := body
	flags := byte(0)
	if compress {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		if _, err := w.Write(body); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		payload = buf.Bytes()
		flags |= 0x01
	}
	out := make([]byte, 5, 5+len(payload))
	out[0] = flags
	binary.BigEndian.PutUint32(out[1:], uint32(len(payload)))
	return append(out, payload...), nil
}

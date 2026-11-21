// Package encoding is the contract's Encoding, which every part composes: a tuple, the values a tuple
// carries, and HKDF(ikm, label, …) (the Crypto API, Encoding).
package encoding

import (
	"encoding/binary"
	"math"
	"unicode/utf8"
)

// Tuple is tuple(a, b, …): u32be(len(a)) ‖ a ‖ u32be(len(b)) ‖ b ‖ …, so no two lists of parts encode
// alike. It never keeps or changes a part, and the slice it returns is new.
//
// A part of 2^32 bytes or more has no u32be length, and is a fault: it panics.
func Tuple(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		if !fits(uint64(len(p))) {
			panic("tuple: a part of 2^32 bytes or more")
		}
		n += 4 + len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = binary.BigEndian.AppendUint32(out, uint32(len(p))) //nolint:gosec // fits checked it above
		out = append(out, p...)
	}
	return out
}

// ParseTuple is the parts of tuple, each u32be(len) ‖ part in turn to its last byte. ok is false where a
// length runs past the end, or fewer than 4 bytes are left for one, which the caller refuses as
// malformed: this package cannot name a refusal. An empty tuple has no parts. Each part is a slice of
// tuple, never a copy, so the caller neither keeps one past tuple nor changes it.
//
// It builds a slice of every part, so a caller reading a tuple from a wire whose parts it may refuse one
// by one checks it with Parses and walks it with Next instead, holding nothing for a part it refuses.
func ParseTuple(tuple []byte) (parts [][]byte, ok bool) {
	if _, ok := Parses(tuple); !ok {
		return nil, false
	}
	for len(tuple) > 0 {
		var part []byte
		part, tuple, _ = Next(tuple)
		parts = append(parts, part)
	}
	return parts, true
}

// Next is a tuple's first part and the rest of the tuple after it, each a slice of tuple, never a copy.
// ok is false where fewer than 4 bytes are left for a length, or the length runs past the end.
func Next(tuple []byte) (part, rest []byte, ok bool) {
	if len(tuple) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(tuple)
	tuple = tuple[4:]
	if uint64(n) > uint64(len(tuple)) {
		return nil, nil, false
	}
	return tuple[:n:n], tuple[n:], true
}

// Parses is whether tuple parses, as ParseTuple's ok, and how many parts it has, found without
// allocating.
func Parses(tuple []byte) (n int, ok bool) {
	for len(tuple) > 0 {
		if _, tuple, ok = Next(tuple); !ok {
			return 0, false
		}
		n++
	}
	return n, true
}

// fits is whether a part of length n has a u32be length.
func fits(n uint64) bool {
	return n <= math.MaxUint32
}

// U64 is an integer as a tuple carries it: its u64be.
func U64(v uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, v)
}

// Text is text as a tuple carries it: its UTF-8, exactly as given, with no normalisation. A locator
// is text, and is carried so. ok is false for text that is not well-formed Unicode, such as bytes that
// are not UTF-8 or the encoding of a surrogate, which the caller refuses as malformed: this package
// cannot name a refusal, since the module root imports it.
func Text(s string) (b []byte, ok bool) {
	if !utf8.ValidString(s) {
		return nil, false
	}
	return []byte(s), true
}

// WellFormed is whether b is text Text takes: well-formed Unicode as UTF-8, checked without copying.
func WellFormed(b []byte) bool {
	return utf8.Valid(b)
}

// UUID is a UUID as a tuple carries it: its 16 bytes, never its text. It takes a sealdcrypto.UUID,
// which this package cannot name, since the module root imports it.
func UUID(u [16]byte) []byte {
	return u[:]
}

// RecipientID is a recipient id as a tuple carries it: its 16 bytes. It takes a
// sealdcrypto.RecipientID.
func RecipientID(id [16]byte) []byte {
	return id[:]
}

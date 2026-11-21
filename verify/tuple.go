package verify

import "github.com/seald-healthcare/crypto-go/internal/encoding"

// Tuple is tuple(parts…): each part behind its length as u32be, so no two lists of parts encode
// alike, and bytes signed or derived over one list can never be read as another.
//
// It never keeps or changes a part, and the slice it returns is new. It encodes the parts it is given
// and nothing else: every tuple the format uses starts with its own label, which the caller puts
// first, and each value is a part only in its one encoding: text as its UTF-8, an integer as its
// u64be and a UUID as its 16 bytes, never its text. A part of 2^32 bytes or more is a fault, and
// panics.
func Tuple(parts ...[]byte) []byte {
	return encoding.Tuple(parts...)
}

package verify

import (
	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/canonical"
)

// CanonicalJSON is the vectors' canonicalJson: value's canonical JSON, RFC 8785 over the JSON Seald
// writes, so that every implementation writes one value as the same bytes, and a hash or signature over
// them is the value's. Members are ordered as RFC 8785 orders them, by their UTF-16 code units, and
// text is written as given, with no normalisation.
//
// It refuses malformed a fraction, an integer of magnitude 2^53 or more, text that is not well-formed
// Unicode, and arrays and objects nested more than 64 deep. A Go map holds no duplicate member.
// A value of a type sealdcrypto.JSON does not hold is a fault, and panics.
//
// It neither keeps nor changes value, and the slice it returns is new.
func CanonicalJSON(value sealdcrypto.JSON) ([]byte, error) {
	return canonical.JSON(value)
}

// ParseCanonicalJSON is the vectors' parseCanonicalJson: the value of bytes, refused malformed unless
// bytes are already canonical, the very bytes CanonicalJSON writes for the value they read as. So a
// hash or signature over bytes it accepts is over its value, and no two texts read as one value.
//
// It refuses malformed bytes that are not JSON, trailing bytes, a duplicate member, text that is not
// well-formed Unicode, whitespace, members out of order, an escape RFC 8785 does not write, and
// every number but an integer of magnitude below 2^53, since CanonicalJSON writes no other, and arrays
// and objects nested more than 64 deep, measured before the text is parsed. A refusal never quotes
// bytes, which may hold a plaintext such as a file's metadata.
//
// The value holds nil, bool, string, int64, []any and map[string]any alone, and shares nothing with
// bytes.
func ParseCanonicalJSON(bytes []byte) (sealdcrypto.JSON, error) {
	return canonical.ParseJSON(bytes)
}

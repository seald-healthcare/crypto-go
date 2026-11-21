package encoding

import (
	"crypto/hkdf"
	"crypto/sha256"
)

// label is a derivation's label. It is unexported, so only an untyped string constant compiles as one,
// and no label comes from a value.
type label string

// HKDF is HKDF(ikm, label, …): HKDF-SHA-256 with an empty salt and tuple(label, …) as its info, length
// bytes long. The bytes it returns are a secret, the caller's to zeroise.
//
// The contract names each label and length, so a length outside 1 to 255 × 32 is a fault: it panics.
func HKDF(ikm []byte, l label, length int, values ...[]byte) []byte {
	if length < 1 || length > 255*sha256.Size {
		panic("HKDF: length out of range")
	}
	return derive(ikm, nil, string(Tuple(append([][]byte{[]byte(l)}, values...)...)), length)
}

// derive is HKDF-SHA-256 (RFC 5869). A nil salt is RFC 5869's salt not provided, which is the empty salt:
// HMAC pads both to the same key.
func derive(ikm, salt []byte, info string, length int) []byte {
	okm, err := hkdf.Key(sha256.New, ikm, salt, info, length)
	if err != nil {
		panic("HKDF: " + err.Error())
	}
	return okm
}

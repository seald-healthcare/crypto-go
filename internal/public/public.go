// Package public is a public key, as every part and every private key names it: the value under
// sealdcrypto.PublicKey (the Crypto API, Keys, and Hashes and identifiers). It makes no check. A Key
// under sealdcrypto.PublicKey is only ever a value that passed verify.ImportPublicKey's, or one a
// private key derived. Any other Key is a key as a body writes it, its algorithm's name and its value
// as written, of an algorithm v1 does not have or a value its import refuses among them, made for its
// export and digest alone, so a body's fingerprint is checked before the key's algorithm and its import
// (the Crypto API, Hashes and identifiers, Key export), and never handed to an operation.
package public

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/seald-healthcare/crypto-go/internal/encoding"
)

// The contract's algorithms, and each public value's size.
const (
	XWing               = "x-wing"
	Ed25519MLDSA65      = "ed25519+ml-dsa-65"
	XWingEd25519MLDSA65 = "x-wing+ed25519+ml-dsa-65"

	XWingSize               = 1216
	Ed25519MLDSA65Size      = 1984
	XWingEd25519MLDSA65Size = XWingSize + Ed25519MLDSA65Size
)

// Key is an algorithm and its public value. Both are strings, so a Key never changes and == compares
// two keys. The zero Key is no key.
type Key struct {
	algorithm string
	value     string
}

// New is the key of algorithm whose public value is value, copied.
func New(algorithm string, value []byte) Key {
	return Key{algorithm: algorithm, value: string(value)}
}

// IsZero is whether k is no key.
func (k Key) IsZero() bool {
	return k.algorithm == ""
}

// Algorithm is k's algorithm's name.
func (k Key) Algorithm() string {
	return k.algorithm
}

// Value is k's public value, in a new slice.
func (k Key) Value() []byte {
	return []byte(k.value)
}

// Export is the key export: tuple("seald/v1/public-key", algorithm, value).
func (k Key) Export() []byte {
	return encoding.Tuple([]byte("seald/v1/public-key"), []byte(k.algorithm), []byte(k.value))
}

// Digest is the key digest: SHA-256 over the export.
func (k Key) Digest() [32]byte {
	return sha256.Sum256(k.Export())
}

// RecipientID is the first 16 bytes of the digest.
func (k Key) RecipientID() [16]byte {
	digest := k.Digest()
	return [16]byte(digest[:16])
}

// Describe is how a value holding k prints, as name, its algorithm and its recipient id in hex, which
// are public. It is what every key handle prints, so formatting one shows nothing secret.
func (k Key) Describe(name string) string {
	if k.IsZero() {
		return name + "(none)"
	}
	id := k.RecipientID()
	return name + "(" + k.algorithm + ", " + hex.EncodeToString(id[:]) + ")"
}

package sealdcrypto

import "github.com/seald-healthcare/crypto-go/internal/public"

// Algorithm is a key's algorithm, which names how its public value and private half are laid out.
type Algorithm string

// The algorithms v1 has.
const (
	// AlgorithmXWing receives: X-Wing, draft -11. Its public value is 1216 bytes and its private half
	// X-Wing's 32-byte seed. A domain key and the backup key.
	AlgorithmXWing Algorithm = public.XWing
	// AlgorithmEd25519MLDSA65 signs: Ed25519 and ML-DSA-65, both always checked. Its public value is
	// 1984 bytes and its private half a 32-byte signing seed. The identity authority and the anchor.
	AlgorithmEd25519MLDSA65 Algorithm = public.Ed25519MLDSA65
	// AlgorithmXWingEd25519MLDSA65 receives as its x-wing half and signs as the rest. Its public value is
	// 3200 bytes and its private half 64: the X-Wing seed, then the signing seed. A device key.
	AlgorithmXWingEd25519MLDSA65 Algorithm = public.XWingEd25519MLDSA65
)

// PublicKey is a public key: its algorithm and its public value, as a wire carries them.
//
// It is opaque, so every PublicKey is either one verify.ImportPublicKey checked or one a private key
// derived, and no operation takes a value that was never checked. It never changes, and == compares two
// keys, so it can key a map.
//
// The zero PublicKey is no key: its Algorithm is "", and an operation given it panics.
type PublicKey public.Key

// Algorithm is the key's algorithm.
func (k PublicKey) Algorithm() Algorithm {
	return Algorithm(public.Key(k).Algorithm())
}

// Value is the key's public value, laid out as its algorithm sets, in a new slice.
func (k PublicKey) Value() []byte {
	return public.Key(k).Value()
}

// String is the key's algorithm and recipient id, in hex.
func (k PublicKey) String() string {
	return public.Key(k).Describe("PublicKey")
}

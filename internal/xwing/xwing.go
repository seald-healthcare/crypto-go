// Package xwing is v1's X-Wing: draft-connolly-cfrg-xwing-kem-11's, and in HPKE draft-ietf-hpke-pq-05's
// MLKEM768-X25519 at 0x647A, which is Go's hpke.MLKEM768X25519 (the Crypto API, X-Wing). The test holds
// Go's to the draft's vectors, so a Go release that moves to another revision fails it.
//
// crypto/hpke decapsulates only inside HPKE, and gives no shared secret out, so the draft's seed
// expansion and combiner are also here, for a key that decapsulates to its shared secret alone (the
// Crypto API, Wraps): each over crypto/sha3, and held to the draft's vectors and to crypto/hpke's.
package xwing

import (
	"crypto/hpke"
	"crypto/sha3"
)

const (
	// SeedSize is the private half: X-Wing's seed.
	SeedSize = 32
	// PublicKeySize is the public value: ML-KEM-768's 1184 bytes, then X25519's 32.
	PublicKeySize = 1216
	// CiphertextSize is the encapsulation: ML-KEM-768's 1088 bytes, then X25519's ephemeral 32.
	CiphertextSize = 1120
	// MLKEMCiphertextSize is the encapsulation's ML-KEM-768 part, which X25519's ephemeral follows.
	MLKEMCiphertextSize = 1088
	// SharedSecretSize is what decapsulating an encapsulation gives: SHA3-256's output.
	SharedSecretSize = 32
	// expandedSize is the seed's expansion: ML-KEM-768's d and z, then X25519's private key.
	expandedSize = 96
)

// label is the draft's XWingLabel, 5c2e2f2f5e5c, which the combiner hashes last.
const label = `\./` + `/^\`

// KEM is v1's X-Wing in HPKE.
func KEM() hpke.KEM {
	return hpke.MLKEM768X25519()
}

// NewPrivateKey is the x-wing key whose private half is seed, expanded as the draft sets. It refuses a
// seed that is not SeedSize bytes, and keeps no reference to it, so the caller zeroises it.
func NewPrivateKey(seed []byte) (hpke.PrivateKey, error) {
	return KEM().NewPrivateKey(seed)
}

// Expand is the draft's expandDecapsulationKey before its key generation: SHAKE256(seed, 96 bytes), whose
// first 64 bytes are ML-KEM-768's d ‖ z, which crypto/mlkem's NewDecapsulationKey768 takes, and whose
// last 32 are X25519's private key. It is a new slice, a secret, the caller's to zeroise. The caller has
// checked that seed is SeedSize bytes.
func Expand(seed []byte) (expanded []byte) {
	return sha3.SumSHAKE256(seed, expandedSize)
}

// Combine is the draft's combiner, SHA3-256(ssM ‖ ssX ‖ ctX ‖ pkX ‖ XWingLabel), the shared secret of an
// encapsulation whose X25519 ephemeral is ctX, under a key whose X25519 public value is pkX. Each input
// is 32 bytes, and ssM and ssX are secrets the caller zeroises. The shared secret is a new slice of
// SharedSecretSize bytes, the caller's to zeroise.
func Combine(ssM, ssX, ctX, pkX []byte) []byte {
	h := sha3.New256() // its Write never fails
	_, _ = h.Write(ssM)
	_, _ = h.Write(ssX)
	_, _ = h.Write(ctX)
	_, _ = h.Write(pkX)
	_, _ = h.Write([]byte(label))
	return h.Sum(nil)
}

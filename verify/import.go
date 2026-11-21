package verify

import (
	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/keyimport"
)

// ImportPublicKey is the vectors' importPublicKey: the key of algorithm whose public value is value, as
// a wire or storage carries it, once value passes each check below. It is the only way a PublicKey is
// made from bytes, so every key an operation takes was checked here, or derived from a private half.
//
// It refuses unsupported an algorithm v1 does not have, and invalid-key:
//   - a value of the wrong length for its algorithm;
//   - an x-wing value whose ML-KEM-768 half fails the encapsulation key check (FIPS 203, section 7.2),
//     or whose X25519 half is a point of small order, whose shared secret is all zero under every
//     private key (RFC 7748, section 6.1), so no key is imported that a wrap to rests on ML-KEM alone;
//   - an x-wing value whose X25519 half is not the canonical encoding of its u-coordinate, 32 bytes
//     little-endian of value 2^255 - 19 or more, bit 255 set among them, so a key has one export, one
//     digest and one recipient id, and X-Wing's combiner hashes the same pk_X when a wrap is made as
//     when it is opened;
//   - an Ed25519 part that is not the canonical encoding of a point (RFC 8032, section 5.1.3), or is a
//     point of small order, so one point has one recipient id, and no Ed25519 key is one on which
//     libraries disagree.
//
// ML-DSA-65's half has no check to make: every value of its length is a key. The value is copied, and
// the caller's slice is neither kept nor changed.
func ImportPublicKey(algorithm sealdcrypto.Algorithm, value []byte) (sealdcrypto.PublicKey, error) {
	return keyimport.Public(algorithm, value)
}

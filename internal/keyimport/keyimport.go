// Package keyimport is the contract's Import of a public value, every check it makes (the Crypto API,
// Keys, and X-Wing), for verify's ImportPublicKey and for whatever else reads a key from bytes, such as
// a certificate's body, which sign checks as verify reads it.
package keyimport

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/mlkem"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/public"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
	"github.com/seald-healthcare/crypto-go/internal/xwing"
)

// Public is the key of algorithm whose public value is value, as a wire or storage carries it, once
// value passes each check below.
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
func Public(algorithm sealdcrypto.Algorithm, value []byte) (sealdcrypto.PublicKey, error) {
	var ok bool
	switch algorithm {
	case sealdcrypto.AlgorithmXWing:
		if len(value) != public.XWingSize {
			return sealdcrypto.PublicKey{}, wrongSize
		}
		ok = xwingImports(value)
	case sealdcrypto.AlgorithmEd25519MLDSA65:
		if len(value) != public.Ed25519MLDSA65Size {
			return sealdcrypto.PublicKey{}, wrongSize
		}
		ok = signingImports(value)
	case sealdcrypto.AlgorithmXWingEd25519MLDSA65:
		if len(value) != public.XWingEd25519MLDSA65Size {
			return sealdcrypto.PublicKey{}, wrongSize
		}
		ok = xwingImports(value[:public.XWingSize]) && signingImports(value[public.XWingSize:])
	default:
		return sealdcrypto.PublicKey{}, refusal.New(sealdcrypto.RefusalKindUnsupported, "an algorithm v1 does not have")
	}
	if !ok {
		return sealdcrypto.PublicKey{}, refusal.New(sealdcrypto.RefusalKindInvalidKey, "a public value that fails its algorithm's check")
	}
	return sealdcrypto.PublicKey(public.New(string(algorithm), value)), nil
}

var wrongSize = refusal.New(sealdcrypto.RefusalKindInvalidKey, "a public value of the wrong length")

// xwingImports is whether value, an x-wing value, is ML-KEM-768's encapsulation key, then an X25519 point
// canonically encoded and not of small order: hpke.MLKEM768X25519 parses the first with
// mlkem.NewEncapsulationKey768, which makes FIPS 203's check, and takes any 32 bytes as the second.
func xwingImports(value []byte) bool {
	if _, err := xwing.KEM().NewPublicKey(value); err != nil {
		return false
	}
	return x25519Imports(value[mlkem.EncapsulationKeySize768:])
}

// signingImports is whether value, an ed25519+ml-dsa-65 value, is Ed25519's key, then ML-DSA-65's.
func signingImports(value []byte) bool {
	if !ed25519Imports(value[:ed25519.PublicKeySize]) {
		return false
	}
	_, err := mldsa.NewPublicKey(mldsa.MLDSA65(), value[ed25519.PublicKeySize:])
	return err == nil
}

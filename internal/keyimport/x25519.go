package keyimport

import (
	"bytes"
	"crypto/ecdh"
)

// The X25519 check ImportPublicKey makes: an x-wing value is refused whose X25519 part is a point of
// small order, whose shared secret is all zero under every private key (RFC 7748, section 6.1).
// X25519 clears the low three bits of every scalar, so a point is of small order exactly where its
// product with one scalar, clamped, is zero, which crypto/ecdh refuses, as long as that scalar is not
// also a multiple of the order of a large subgroup of the curve or of its twist, which the test
// checks.

// smallOrderProbe is the scalar X25519's part is multiplied by, a constant: the point is public, so the
// check need not be constant time, and the product is dropped.
var smallOrderProbe = func() *ecdh.PrivateKey {
	k, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		panic("verify: " + err.Error())
	}
	return k
}()

// canonicalU is whether b, 32 bytes, is the canonical encoding of an X25519 u-coordinate: its value,
// little-endian over all 256 bits, below p = 2^255 - 19, so bit 255 is clear. X25519 reads any 32 bytes
// as a u-coordinate, clearing bit 255 and reducing modulo p (RFC 7748, section 5), so the 19 values from
// p to 2^255 - 1, and every value with bit 255 set, name a point another encoding also names, under
// another export, digest and recipient id. The bytes are public, so the comparison need not be constant
// time.
func canonicalU(b []byte) bool {
	if b[31]&0x80 != 0 {
		return false
	}
	// Below 2^255, u is p or more only when bits 8 to 254 are all set and its lowest byte is 0xed or
	// more: p is 0x7fff…ffed.
	if b[31] != 0x7f {
		return true
	}
	for _, c := range b[1:31] {
		if c != 0xff {
			return true
		}
	}
	return b[0] < 0xed
}

// x25519Imports is whether b, 32 bytes, is an X25519 point ImportPublicKey imports: the canonical
// encoding of its u-coordinate, and not of small order.
func x25519Imports(b []byte) bool {
	return canonicalU(b) && !X25519SmallOrder(b)
}

// X25519SmallOrder is whether b, 32 bytes, encodes an X25519 point of small order, canonical or not,
// whose shared secret is all zero under every private key (RFC 7748, section 6.1): an x-wing value's
// X25519 part at import, and a wrap's X25519 ephemeral, which the Crypto API, X-Wing, refuses wherever
// it is met. b is public. Bytes crypto/ecdh does not take as a point, of another length or in FIPS
// 140-only mode, where it refuses X25519, read as of small order, so a check that cannot run refuses.
func X25519SmallOrder(b []byte) bool {
	p, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return true
	}
	_, err = smallOrderProbe.ECDH(p)
	return err != nil
}

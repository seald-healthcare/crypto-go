package keyimport

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
)

// The Ed25519 checks ImportPublicKey makes: a public key is refused unless it is the canonical
// encoding of a point on the curve (RFC 8032, section 5.1.3), and not of small order. crypto/ed25519
// makes none of these checks at import, and decodes as most libraries do rather than as RFC 8032
// does, so they are made here, over public bytes, with no arithmetic on the curve: the encoding and
// the points of small order are fixed, and only whether a point is on the curve is the standard
// library's.

// canonicalPoint is whether b, 32 bytes, encodes a y below p = 2^255 - 19, and does not set the sign of an
// x of 0, which only y = 1 and y = p - 1 have. RFC 8032 refuses both, and crypto/ed25519 accepts both.
func canonicalPoint(b []byte) bool {
	if bytes.Equal(b, xZeroSigned[0]) || bytes.Equal(b, xZeroSigned[1]) {
		return false
	}
	// y, little-endian with the sign bit cleared, is p or more only when bits 8 to 254 are all set
	// and its lowest byte is 0xed or more: p is 0x7fff…ffed.
	if b[31]&0x7f != 0x7f {
		return true
	}
	for _, c := range b[1:31] {
		if c != 0xff {
			return true
		}
	}
	return b[0] < 0xed
}

// xZeroSigned is y = 1 and y = p - 1, the two points whose x is 0, each with the sign bit set.
var xZeroSigned = [2][]byte{
	mustHex("0100000000000000000000000000000000000000000000000000000000000080"),
	mustHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
}

// smallOrder is the canonical encoding of each of the curve's 8 points of small order, whose order
// divides its cofactor, 8: the identity, the point of order 2, the two of order 4 and the four of
// order 8. The test checks each through X25519, which refuses the same points in their Montgomery
// form.
var smallOrder = [8][]byte{
	mustHex("0100000000000000000000000000000000000000000000000000000000000000"),
	mustHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
	mustHex("0000000000000000000000000000000000000000000000000000000000000000"),
	mustHex("0000000000000000000000000000000000000000000000000000000000000080"),
	mustHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
	mustHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
	mustHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
	mustHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
}

// ofSmallOrder is whether b, a canonical encoding, is a point of small order.
func ofSmallOrder(b []byte) bool {
	for _, p := range smallOrder {
		if bytes.Equal(b, p) {
			return true
		}
	}
	return false
}

// onTheCurve is whether b decodes to a point, as crypto/ed25519 decodes a public key before it
// verifies. Its only word on that is the error Verify returns: a point it decodes fails a signature of
// zeros as "invalid signature", and one it cannot as "bad public key". Any other answer, such as a
// wording a later Go chooses, is taken as no point, so a change refuses every key rather than admitting
// one off the curve, and the tests fail.
func onTheCurve(b []byte) bool {
	err := ed25519.VerifyWithOptions(ed25519.PublicKey(b), nil, make([]byte, ed25519.SignatureSize), &ed25519.Options{})
	return err != nil && err.Error() == "ed25519: invalid signature"
}

// ed25519Imports is whether b, 32 bytes, is an Ed25519 public key ImportPublicKey imports.
func ed25519Imports(b []byte) bool {
	return canonicalPoint(b) && !ofSmallOrder(b) && onTheCurve(b)
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

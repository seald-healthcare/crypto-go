package verify

import (
	"crypto/subtle"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
)

// CodeSize is a setup code's or a guest code's length: 32 random bytes.
const CodeSize = 32

// CodeTextSize is the length of a code's one text.
const CodeTextSize = 52

// EncodeCode writes a setup code or a guest code, CodeSize bytes, as its one text: lower-case base32
// without padding, CodeTextSize characters, in a new slice for the caller to zeroise. A code of
// another length is a fault, and panics.
func EncodeCode(code []byte) []byte {
	if len(code) != CodeSize {
		panic("encodeCode: a code of another length than 32 bytes")
	}
	return base32Encode(code)
}

var notACode = refusal.New(sealdcrypto.RefusalKindMalformed, "a code that is not its one text")

// DecodeCode reads a setup code or a guest code from its one text, and returns its CodeSize bytes in a
// new slice for the caller to zeroise. Any other text is refused malformed, white space, upper case
// and padding among it: what takes a code from a person cleans what they typed before it is read.
func DecodeCode(text []byte) ([]byte, error) {
	if len(text) != CodeTextSize {
		return nil, notACode
	}
	code, ok := base32Decode(text)
	if !ok {
		return nil, notACode
	}
	return code, nil
}

// base32Encode is RFC 4648's base32 in lower case without padding, over any length. A code is a
// secret, so no branch or table index depends on a byte of it.
func base32Encode(src []byte) []byte {
	out := make([]byte, 0, (len(src)*8+4)/5)
	var acc uint32
	n := 0
	for _, b := range src {
		acc = acc<<8 | uint32(b)
		n += 8
		for n >= 5 {
			n -= 5
			out = append(out, symbol(byte(acc>>n)&31)) //nolint:gosec // the low bits alone are kept
		}
	}
	if n > 0 {
		out = append(out, symbol(byte(acc<<(5-n))&31)) //nolint:gosec // the low bits alone are kept
	}
	return out
}

// base32Decode is base32Encode's inverse, false for a length no bytes encode to, a character outside
// the alphabet, or a trailing bit set. Every character is read whatever the ones before it.
func base32Decode(text []byte) ([]byte, bool) {
	switch len(text) % 8 {
	case 1, 3, 6:
		return nil, false
	}
	out := make([]byte, 0, len(text)*5/8)
	var acc uint32
	n, bad := 0, 0
	for _, c := range text {
		v, ok := value(c)
		bad |= ok ^ 1
		acc = acc<<5 | uint32(v)
		if n += 5; n >= 8 {
			n -= 8
			out = append(out, byte(acc>>n)) //nolint:gosec // the low bits alone are kept
		}
	}
	bad |= subtle.ConstantTimeEq(int32(acc&(1<<n-1)), 0) ^ 1 //nolint:gosec // below 2^4
	if bad != 0 {
		clear(out)
		return nil, false
	}
	return out, true
}

// symbol is the character of a 5-bit value: a to z, then 2 to 7.
func symbol(v byte) byte {
	letter := subtle.ConstantTimeLessOrEq(int(v), 25)
	return byte(subtle.ConstantTimeSelect(letter, int(v)+'a', int(v)+'2'-26)) //nolint:gosec // below 128
}

// value is c's 5-bit value, and 1 where c is in the alphabet, 0 otherwise.
func value(c byte) (byte, int) {
	letter := subtle.ConstantTimeLessOrEq('a', int(c)) & subtle.ConstantTimeLessOrEq(int(c), 'z')
	digit := subtle.ConstantTimeLessOrEq('2', int(c)) & subtle.ConstantTimeLessOrEq(int(c), '7')
	v := subtle.ConstantTimeSelect(letter, int(c)-'a', 0) | subtle.ConstantTimeSelect(digit, int(c)-'2'+26, 0)
	return byte(v), letter | digit //nolint:gosec // below 32
}

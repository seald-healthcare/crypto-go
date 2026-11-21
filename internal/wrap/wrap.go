// Package wrap seals a wrap for seal and open: HPKE base mode, one message, with a wrap context as its
// additional data. It holds no private key and opens no wrap, so seal links it: a wrap is opened by
// internal/unwrap, which open alone links.
package wrap

import (
	"crypto/hpke"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/encoding"
	"github.com/seald-healthcare/crypto-go/internal/public"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
	"github.com/seald-healthcare/crypto-go/internal/xwing"
)

// Info is HPKE's info for every wrap.
const Info = "seald/v1/wrap"

const (
	// EncSize is a wrap's enc: X-Wing's ciphertext.
	EncSize = xwing.CiphertextSize
	// TagSize is AES-256-GCM's tag, which the ciphertext after enc ends with.
	TagSize = 16
	// SecretSize is every secret v1 wraps: a content key, a domain key's X-Wing seed, under domain-key and
	// epoch-link, a tokenisation key and a re-founding's challenge.
	SecretSize = 32
	// Size is a wrap of a secret of SecretSize: enc, then the secret's ciphertext and its tag.
	Size = EncSize + SecretSize + TagSize
)

// Suite is HPKE's KDF and AEAD for a wrap: HKDF-SHA256, 0x0001, and AES-256-GCM, 0x0002. The KEM is
// xwing.KEM, 0x647A.
func Suite() (hpke.KDF, hpke.AEAD) {
	return hpke.HKDFSHA256(), hpke.AES256GCM()
}

var malformedText = refusal.New(sealdcrypto.RefusalKindMalformed, "text that is not well-formed Unicode")

// AAD is a wrap's additional data: tuple(purpose, tenant id, …context), with the context after the tenant
// id as its purpose's row of Wraps lays it out.
//
// The caller gives the context both when wrapping and when unwrapping, so what Wraps makes a fault is
// one, and panics, naming op: a nil context, a pointer, an empty locator in a content-key, domain-key or
// epoch-link context, an epoch below 1 in a domain-key, epoch-link or tokenisation-key context, a linked
// epoch not below the one it is wrapped to in an epoch-link context. A fault is raised whatever the
// input, so each is checked before anything is refused. Only then is the context's text read, and a
// locator or a segment that is not well-formed Unicode refused malformed, before the caller checks any
// byte of a wrap.
func AAD(op string, context sealdcrypto.WrapContext) ([]byte, error) {
	var parts [][]byte
	switch c := context.(type) {
	case sealdcrypto.WrapContextContentKey:
		checkLocator(op, c.Locator)
		locator, ok1 := encoding.Text(string(c.Locator))
		segment, ok2 := encoding.Text(c.Segment)
		if !ok1 || !ok2 {
			return nil, malformedText
		}
		parts = [][]byte{[]byte("content-key"), encoding.UUID(c.Tenant), locator, encoding.U64(c.Version), segment}
	case sealdcrypto.WrapContextDomainKey:
		checkLocator(op, c.DomainRoot)
		checkEpoch(op, c.Epoch)
		root, ok := encoding.Text(string(c.DomainRoot))
		if !ok {
			return nil, malformedText
		}
		parts = [][]byte{[]byte("domain-key"), encoding.UUID(c.Tenant), root, encoding.U64(c.Epoch)}
	case sealdcrypto.WrapContextEpochLink:
		checkLocator(op, c.DomainRoot)
		checkEpoch(op, c.LinkedEpoch)
		checkEpoch(op, c.Epoch)
		if c.LinkedEpoch >= c.Epoch {
			panic(op + ": a linked epoch not below the one it is wrapped to")
		}
		root, ok := encoding.Text(string(c.DomainRoot))
		if !ok {
			return nil, malformedText
		}
		parts = [][]byte{[]byte("epoch-link"), encoding.UUID(c.Tenant), root, encoding.U64(c.LinkedEpoch), encoding.U64(c.Epoch)}
	case sealdcrypto.WrapContextTokenisationKey:
		checkEpoch(op, c.Epoch)
		parts = [][]byte{[]byte("tokenisation-key"), encoding.UUID(c.Tenant), encoding.U64(c.Epoch)}
	case sealdcrypto.WrapContextRefoundingChallenge:
		parts = [][]byte{[]byte("refounding-challenge"), encoding.UUID(c.Tenant), encoding.UUID(c.Refounding)}
	default:
		panic(op + ": no wrap context")
	}
	return encoding.Tuple(parts...), nil
}

// checkLocator is a locator a context gives, non-empty text. An empty one is a fault.
func checkLocator(op string, locator sealdcrypto.Locator) {
	if locator == "" {
		panic(op + ": an empty locator")
	}
}

// checkEpoch is an epoch a context gives, an integer from 1, since the founding mints epoch 1. One below
// 1 is a fault.
func checkEpoch(op string, epoch uint64) {
	if epoch < 1 {
		panic(op + ": an epoch below 1")
	}
}

// Seal is secret wrapped to key under context: enc ‖ ciphertext, 1120 bytes, then the secret's 32 plus
// 16, Size in all. key is an x-wing key, or a device key's x-wing half; one that only signs is refused
// invalid-key. X-Wing draws the encapsulation from crypto/rand. The zero key and a secret that is not
// SecretSize bytes are faults, and so is context as AAD sets.
func Seal(key sealdcrypto.PublicKey, secret []byte, context sealdcrypto.WrapContext) ([]byte, error) {
	k := public.Key(key)
	if k.IsZero() {
		panic("wrap: no key")
	}
	if len(secret) != SecretSize {
		panic("wrap: a secret that is not 32 bytes")
	}
	aad, err := AAD("wrap", context)
	if err != nil {
		return nil, err
	}
	var value []byte
	switch k.Algorithm() {
	case public.XWing:
		value = k.Value()
	case public.XWingEd25519MLDSA65:
		value = k.Value()[:public.XWingSize]
	default:
		return nil, refusal.New(sealdcrypto.RefusalKindInvalidKey, "a wrap to a key that only signs")
	}
	pk, err := xwing.KEM().NewPublicKey(value)
	if err != nil {
		panic("wrap: an x-wing value that did not import: " + err.Error())
	}
	kdf, aead := Suite()
	enc, s, err := hpke.NewSender(pk, kdf, aead, []byte(Info))
	if err != nil {
		// The only error left is X25519's, whose shared secret with a point of small order is all zero,
		// which crypto/ecdh refuses, and which import refuses first.
		panic("wrap: an x-wing key of small order: " + err.Error())
	}
	ciphertext, err := s.Seal(aad, secret)
	if err != nil {
		panic("wrap: " + err.Error())
	}
	return append(enc, ciphertext...), nil
}

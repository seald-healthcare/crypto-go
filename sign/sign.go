package sign

import (
	"bytes"
	"context"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/private"
	"github.com/seald-healthcare/crypto-go/internal/public"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
	"github.com/seald-healthcare/crypto-go/internal/signature"
)

// Signer is what signs a message: a *SigningKey or an *open.DeviceKey this library holds, or a key held
// elsewhere, such as in a key store over a network.
//
// Only Sign and Certify call it. They hand Sign the whole message, tuple("seald/v1/signature",
// label, payload), and ctx, which a key store over a network honours as Go's calls do; a local key
// ignores it. Sign returns Ed25519's signature, then ML-DSA-65's, 3373 bytes, under PublicKey, or an
// error of the signer's own, which Sign and Certify return unchanged.
// They verify what it returns before they return it, so a signer that signs under another key or
// returns broken bytes is caught where it signs, and one needs no check of its own beyond signing
// what it is given.
//
// A signer outside this library signs only what Sign hands it: signing other bytes under a key that
// signs this format's messages is signing without a label, which the format forbids, as a signature
// over other bytes could then pass for one made under a label.
type Signer interface {
	// PublicKey is the key the signer signs under: an ed25519+ml-dsa-65 key, or a device key.
	PublicKey() sealdcrypto.PublicKey
	// Sign is the signature over message, or the signer's own error.
	Sign(ctx context.Context, message []byte) ([]byte, error)
}

var _ Signer = (*SigningKey)(nil)

// Sign is the vectors' sign: signer's signature over tuple("seald/v1/signature", label, payload), 3373
// bytes, Ed25519's signature and then ML-DSA-65's. payload is the bytes the protocol that uses label
// names, canonical JSON unless that protocol says otherwise.
//
// Sign takes payload as given and reads none of it, as the Crypto API's Signatures sets: a body's form
// binds whoever lays the body out, so the caller lays out each body it signs as the Crypto API's Bodies
// sets it, and a body that a reader refuses, such as one with an empty locator, is the caller's fault,
// which Sign does not catch. Certify alone checks its body.
//
// It refuses unsupported a label v1 does not have, and invalid-key a signer whose key cannot sign, an
// x-wing key, before calling it. What the signer returns is verified under its PublicKey before it is
// returned, and refused signature-invalid where it does not verify. An error the signer returns is
// returned unchanged, and is neither a refusal nor a fault, so the caller tells the two apart with
// errors.As against the signer's own types; a signer whose error is itself a *sealdcrypto.Refusal is
// indistinguishable from a refusal.
//
// A nil signer, or one whose PublicKey is the zero PublicKey, is a fault, and panics.
func Sign(ctx context.Context, signer Signer, label sealdcrypto.Label, payload []byte) ([]byte, error) {
	_, sig, err := signed(ctx, "sign", signer, label, payload)
	return sig, err
}

// signed is Sign for op: the message and signer's signature over it, a new slice, each checked as Sign
// sets.
func signed(ctx context.Context, op string, signer Signer, label sealdcrypto.Label, payload []byte) (message, sig []byte, err error) {
	key := keyOf(op, signer)
	message, ok := signature.Message(label, payload)
	if !ok {
		return nil, nil, refusal.New(sealdcrypto.RefusalKindUnsupported, "a label v1 does not have")
	}
	if key.Algorithm() == public.XWing {
		return nil, nil, refusal.New(sealdcrypto.RefusalKindInvalidKey, "a key that cannot sign")
	}
	sig, err = signer.Sign(ctx, message)
	if err != nil {
		return nil, nil, err
	}
	if !signature.Verify(key, message, sig) {
		return nil, nil, refusal.New(sealdcrypto.RefusalKindSignatureInvalid, "a signature the signer returned that does not verify under its key")
	}
	return message, bytes.Clone(sig), nil
}

// keyOf is signer's key, and a fault, for op, where there is no signer or it has no key.
func keyOf(op string, signer Signer) public.Key {
	if signer == nil {
		panic(op + ": no signer")
	}
	key := public.Key(signer.PublicKey())
	if key.IsZero() {
		panic(op + ": no key")
	}
	return key
}

// Sign is the key's signature over message, as a Signer's is, for Sign and Certify to call. It signs
// only a message they lay out, tuple("seald/v1/signature", label, payload) under a label v1 has, and
// refuses any other without signing it, malformed or, for its label, unsupported: so calling it
// directly signs nothing that Sign would not, and the key never signs without a label. ctx is not
// used. The zero SigningKey is a fault, and panics.
func (k *SigningKey) Sign(_ context.Context, message []byte) ([]byte, error) {
	s := (*private.Signing)(k)
	if k == nil || s.Public().IsZero() {
		panic("sign: no key")
	}
	if err := signature.CheckMessage(message); err != nil {
		return nil, err
	}
	return s.Sign(message), nil
}

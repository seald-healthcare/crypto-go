package open

import (
	"context"
	"crypto/subtle"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/private"
	"github.com/seald-healthcare/crypto-go/internal/public"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
	"github.com/seald-healthcare/crypto-go/internal/unwrap"
)

// Unwrap opens a wrap to key under context and returns the secret, 32 bytes in a new slice for the
// caller to zeroise. A device key unwraps as its Receiving().
//
// Name the context you expect from what you are opening, never one read from the wrap or beside it: the
// context is what binds the secret to its purpose and tenant. An opened wrap proves the context and the
// key, not who wrapped it, so check a content key against its envelope and a share against its
// registration.
func Unwrap(key *ReceivingKey, wrapped []byte, context sealdcrypto.SecretWrapContext) ([]byte, error) {
	if key == nil || (*private.Receiving)(key).Public().IsZero() {
		panic("unwrap: no key")
	}
	return unwrap.Open("unwrap", (*private.Receiving)(key).HPKE(), wrapped, context)
}

// UnwrapDomainKey opens a domain key's wrap, a slice or an epoch link, under context, and returns the
// domain key once its key digest is keyDigest, a new handle for the caller to Zeroise.
//
// Take keyDigest from an epoch body whose signature you verified, never from the wrap or beside it
// unsigned. A digest proves nothing on its own: whoever holds the slices can wrap a key of its own to
// any device and hand out its digest. So use a key opened from a slice only once the epoch's body,
// rebuilt with verify.CanonicalJSON, verifies under sealdcrypto.LabelEpoch and the signer's card passes
// verify.VerifyKeptCard under your anchor; refuse the slice signature-invalid otherwise. A link needs no signature,
// since a wrong key opens nothing.
func UnwrapDomainKey(key *ReceivingKey, wrapped []byte, context sealdcrypto.DomainKeyWrapContext, keyDigest []byte) (*ReceivingKey, error) {
	if key == nil || (*private.Receiving)(key).Public().IsZero() {
		panic("unwrapDomainKey: no key")
	}
	seed, err := unwrap.Open("unwrapDomainKey", (*private.Receiving)(key).HPKE(), wrapped, context)
	if err != nil {
		return nil, err
	}
	return domainKeyOf(seed, keyDigest)
}

var otherKeyDigest = refusal.New(sealdcrypto.RefusalKindAuthenticationFailed, "a domain key whose key digest is not its epoch's")

// domainKeyOf zeroises seed, and the key it made where the digest differs. The digest is compared only
// once the wrap opens, since there is no seed before, in constant time.
func domainKeyOf(seed, keyDigest []byte) (*ReceivingKey, error) {
	defer clear(seed)
	k, err := private.NewReceiving(seed)
	if err != nil {
		// A wrap opens to a secret of 32 bytes alone, and every 32 bytes are an X-Wing seed.
		panic("unwrapDomainKey: " + err.Error())
	}
	digest := k.Public().Digest()
	if subtle.ConstantTimeCompare(digest[:], keyDigest) != 1 {
		k.Zeroise()
		return nil, otherKeyDigest
	}
	return (*ReceivingKey)(k), nil
}

// Receiver decapsulates a wrap's enc for UnwrapWith: a key held here, or one held elsewhere, such as in a
// hardware key store.
//
// Its shared secret opens every wrap to its key under any context, so a receiver decapsulates only for a
// caller it would let unwrap, and never an enc a caller chooses for that caller to keep.
type Receiver interface {
	// PublicKey is the x-wing key or device key the receiver decapsulates under.
	PublicKey() sealdcrypto.PublicKey
	// Decapsulate returns X-Wing's shared secret of enc in a new slice, or the receiver's own error, which
	// UnwrapWith returns unchanged.
	Decapsulate(ctx context.Context, enc []byte) ([]byte, error)
}

var (
	_ Receiver = (*ReceivingKey)(nil)
	_ Receiver = (*DeviceKey)(nil)
)

// UnwrapWith is Unwrap under a receiver that holds its key elsewhere. The receiver is asked only once the
// wrap passes every check of its own bytes, its length and its ephemeral among them.
//
// A receiver's own error is returned unchanged, told apart from a refusal with errors.As; a receiver
// whose error is itself a *sealdcrypto.Refusal is indistinguishable from one. It is a fault under
// GODEBUG=fips140=only.
func UnwrapWith(ctx context.Context, receiver Receiver, wrapped []byte, wrapContext sealdcrypto.SecretWrapContext) ([]byte, error) {
	return unwrapWith(ctx, "unwrapWith", receiver, wrapped, wrapContext)
}

// UnwrapDomainKeyWith is UnwrapDomainKey under a receiver that holds its key elsewhere, which is asked
// whatever keyDigest, since the digest is compared once the wrap opens.
func UnwrapDomainKeyWith(ctx context.Context, receiver Receiver, wrapped []byte, wrapContext sealdcrypto.DomainKeyWrapContext, keyDigest []byte) (*ReceivingKey, error) {
	seed, err := unwrapWith(ctx, "unwrapDomainKeyWith", receiver, wrapped, wrapContext)
	if err != nil {
		return nil, err
	}
	return domainKeyOf(seed, keyDigest)
}

func unwrapWith(ctx context.Context, op string, receiver Receiver, wrapped []byte, wrapContext sealdcrypto.WrapContext) ([]byte, error) {
	if receiver == nil {
		panic(op + ": no receiver")
	}
	key := public.Key(receiver.PublicKey())
	if key.IsZero() {
		panic(op + ": no key")
	}
	return unwrap.OpenWith(op, key, wrapped, wrapContext, func(enc []byte) ([]byte, error) {
		return receiver.Decapsulate(ctx, enc)
	})
}

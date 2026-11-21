package open

import (
	"context"
	"fmt"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/private"
	"github.com/seald-healthcare/crypto-go/internal/public"
	"github.com/seald-healthcare/crypto-go/internal/unwrap"
	"github.com/seald-healthcare/crypto-go/sign"
)

// ReceivingKey is a private x-wing key: a domain key, or the backup key once rebuilt. Use it through a
// pointer; the zero key is a fault.
//
// It prints only its algorithm and recipient id under fmt, but a printer that follows pointers past fmt
// can reach its secrets: never hand a key to one. Compare keys by their PublicKey().
type ReceivingKey private.Receiving

// PublicKey is the key's public half.
func (k *ReceivingKey) PublicKey() sealdcrypto.PublicKey {
	return sealdcrypto.PublicKey((*private.Receiving)(k).Public())
}

// Decapsulate returns X-Wing's shared secret of enc under the key, in a new slice for the caller to
// zeroise. ctx is not used.
//
// The shared secret opens the wrap under any context, as the key would, so hand it only to what may
// unwrap that wrap, and never log or keep it. It is a fault under GODEBUG=fips140=only.
func (k *ReceivingKey) Decapsulate(_ context.Context, enc []byte) ([]byte, error) {
	if k == nil || (*private.Receiving)(k).Public().IsZero() {
		panic("decapsulate: no key")
	}
	return unwrap.Decapsulate((*private.Receiving)(k), enc)
}

// Format writes the key's algorithm and recipient id, under every verb.
func (k ReceivingKey) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, k.String())
}

// String is the key's algorithm and recipient id, as Format writes them.
func (k ReceivingKey) String() string {
	return public.Key(k.PublicKey()).Describe("ReceivingKey")
}

// GoString is String, so %#v prints nothing secret either.
func (k ReceivingKey) GoString() string { return k.String() }

// Zeroise overwrites the key's seed and leaves it, and every copy of its handle, the zero key. The key
// crypto/hpke expanded cannot be overwritten, and lives until the garbage collector frees it. Not safe
// while another goroutine uses the key.
func (k *ReceivingKey) Zeroise() {
	if k != nil {
		(*private.Receiving)(k).Zeroise()
	}
}

// DeviceKey is a device's private key: it receives as its x-wing half and signs as the rest. It is a
// handle as ReceivingKey is, a sign.Signer and a Receiver. Use it through a pointer; the zero key is a
// fault.
type DeviceKey private.Device

// PublicKey is the key's public half: the x-wing value, then the ed25519+ml-dsa-65 value.
func (k *DeviceKey) PublicKey() sealdcrypto.PublicKey {
	return sealdcrypto.PublicKey((*private.Device)(k).Public())
}

// Receiving is the key's x-wing half, which a wrap to the device key is to.
func (k *DeviceKey) Receiving() *ReceivingKey {
	return (*ReceivingKey)((*private.Device)(k).Receiving())
}

// Sign signs message with the key's ed25519+ml-dsa-65 half, for sign.Sign and sign.Certify, and refuses
// a message they would not lay out. ctx is not used.
func (k *DeviceKey) Sign(ctx context.Context, message []byte) ([]byte, error) {
	if k == nil || (*private.Device)(k).Public().IsZero() {
		panic("sign: no key")
	}
	return (*sign.SigningKey)((*private.Device)(k).Signing()).Sign(ctx, message)
}

// Decapsulate is its Receiving()'s Decapsulate. ctx is not used.
func (k *DeviceKey) Decapsulate(ctx context.Context, enc []byte) ([]byte, error) {
	if k == nil || (*private.Device)(k).Public().IsZero() {
		panic("decapsulate: no key")
	}
	return k.Receiving().Decapsulate(ctx, enc)
}

// Format writes the key's algorithm and recipient id, under every verb.
func (k DeviceKey) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, k.String())
}

// String is the key's algorithm and recipient id, as Format writes them.
func (k DeviceKey) String() string {
	return public.Key(k.PublicKey()).Describe("DeviceKey")
}

// GoString is String, so %#v prints nothing secret either.
func (k DeviceKey) GoString() string { return k.String() }

// Zeroise wipes both halves of the key, and leaves it, every copy of its handle and its Receiving() the
// zero key. Not safe while another goroutine uses the key.
func (k *DeviceKey) Zeroise() {
	if k != nil {
		(*private.Device)(k).Zeroise()
	}
}

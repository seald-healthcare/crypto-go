package open

import (
	"crypto/rand"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/private"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
	"github.com/seald-healthcare/crypto-go/sign"
)

// PrivateKey is a private key this library holds: a *ReceivingKey, a *sign.SigningKey or a *DeviceKey,
// which ImportPrivateKey returns and ExportPrivateKey takes. No other type satisfies it, so a caller
// switches on those three alone.
type PrivateKey interface {
	// PublicKey is the key's public half.
	PublicKey() sealdcrypto.PublicKey
	private.Sealed
}

var (
	_ PrivateKey = (*ReceivingKey)(nil)
	_ PrivateKey = (*sign.SigningKey)(nil)
	_ PrivateKey = (*DeviceKey)(nil)

	_ sign.Signer = (*DeviceKey)(nil)
)

// GenerateDeviceKey is a fresh device key. Its private half is 64 bytes from crypto/rand, zeroised once
// the key is made from them. It never fails.
func GenerateDeviceKey() *DeviceKey {
	seed := make([]byte, private.DeviceSeedSize)
	defer clear(seed)
	_, _ = rand.Read(seed)
	k, err := private.NewDevice(seed)
	if err != nil {
		panic("generateDeviceKey: " + err.Error())
	}
	return (*DeviceKey)(k)
}

// GenerateReceivingKey is a fresh x-wing key, such as a domain key's next epoch. Its private half is
// X-Wing's 32-byte seed from crypto/rand, zeroised once the key is made from it. It never fails.
func GenerateReceivingKey() *ReceivingKey {
	seed := make([]byte, private.XWingSeedSize)
	defer clear(seed)
	_, _ = rand.Read(seed)
	k, err := private.NewReceiving(seed)
	if err != nil {
		panic("generateReceivingKey: " + err.Error())
	}
	return (*ReceivingKey)(k)
}

// ImportPrivateKey is the vectors' importPrivateKey: the key of algorithm whose private half is bytes,
// with its public half derived from bytes. It returns a *ReceivingKey for x-wing, whose private half is
// X-Wing's 32-byte seed, a *sign.SigningKey for ed25519+ml-dsa-65, whose private half is a 32-byte
// signing seed, and a *DeviceKey for x-wing+ed25519+ml-dsa-65, whose private half is 64 bytes, the
// X-Wing seed then the signing seed.
//
// Where expected is not nil, the derived public half must equal it, algorithm and value, or the import
// is refused invalid-key: a caller holding the public key a private half should have passes it, so a
// private half that is not that key's, from storage or a wire, is never used as it.
//
// It refuses unsupported an algorithm v1 does not have, and invalid-key bytes of the wrong size. It
// copies bytes, which the caller zeroises, and zeroises the key it made of them where it refuses it.
func ImportPrivateKey(algorithm sealdcrypto.Algorithm, bytes []byte, expected *sealdcrypto.PublicKey) (PrivateKey, error) {
	var key PrivateKey
	switch algorithm {
	case sealdcrypto.AlgorithmXWing:
		if len(bytes) != private.XWingSeedSize {
			return nil, refusal.New(sealdcrypto.RefusalKindInvalidKey, "a private half of the wrong size")
		}
		k, err := private.NewReceiving(bytes)
		if err != nil {
			return nil, refusal.New(sealdcrypto.RefusalKindInvalidKey, "a private half that does not import")
		}
		key = (*ReceivingKey)(k)
	case sealdcrypto.AlgorithmEd25519MLDSA65:
		// sign.ImportSigningKey's, so a key imported in sign and in open is one key alike.
		k, err := sign.ImportSigningKey(bytes, nil)
		if err != nil {
			return nil, err
		}
		key = k
	case sealdcrypto.AlgorithmXWingEd25519MLDSA65:
		if len(bytes) != private.DeviceSeedSize {
			return nil, refusal.New(sealdcrypto.RefusalKindInvalidKey, "a private half of the wrong size")
		}
		k, err := private.NewDevice(bytes)
		if err != nil {
			return nil, refusal.New(sealdcrypto.RefusalKindInvalidKey, "a private half that does not import")
		}
		key = (*DeviceKey)(k)
	default:
		return nil, refusal.New(sealdcrypto.RefusalKindUnsupported, "an algorithm v1 does not have")
	}
	return asExpected(key, expected)
}

// asExpected is key where expected is nil or is key's public half. Otherwise the import is refused
// invalid-key, and key, which no caller holds, is zeroised first, so its private half is not left to the
// garbage collector, as sign.ImportSigningKey zeroises the key it refuses.
func asExpected(key PrivateKey, expected *sealdcrypto.PublicKey) (PrivateKey, error) {
	if expected == nil || key.PublicKey() == *expected {
		return key, nil
	}
	switch k := key.(type) {
	case *ReceivingKey:
		k.Zeroise()
	case *sign.SigningKey:
		k.Zeroise()
	case *DeviceKey:
		k.Zeroise()
	}
	return nil, refusal.New(sealdcrypto.RefusalKindInvalidKey, "a private half that is not the key expected")
}

// ExportPrivateKey is key's private half, laid out as ImportPrivateKey takes it, in a new slice. It is
// for the platform's custody that seals a device key, and for a domain key's seed to wrap.
//
// The bytes are the key itself: the caller wraps them, or zeroises them with Zeroise once done, and
// never logs, stores or sends them bare. A nil key, or the zero value of a handle, is a fault, and
// panics.
func ExportPrivateKey(key PrivateKey) []byte {
	switch k := key.(type) {
	case *ReceivingKey:
		if k != nil && !(*private.Receiving)(k).Public().IsZero() {
			return (*private.Receiving)(k).Seed()
		}
	case *sign.SigningKey:
		if k != nil && !(*private.Signing)(k).Public().IsZero() {
			return (*private.Signing)(k).Seed()
		}
	case *DeviceKey:
		if k != nil && !(*private.Device)(k).Public().IsZero() {
			return (*private.Device)(k).Seed()
		}
	}
	panic("exportPrivateKey: no key")
}

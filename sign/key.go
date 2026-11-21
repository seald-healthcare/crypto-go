package sign

import (
	"crypto/rand"
	"fmt"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/encoding"
	"github.com/seald-healthcare/crypto-go/internal/private"
	"github.com/seald-healthcare/crypto-go/internal/public"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
)

// SigningKey is a private ed25519+ml-dsa-65 key this library holds: the identity authority or the
// anchor, where no key store holds it.
//
// It is a handle, and a Signer. It has no field, and its Sign signs only a message under a label, so
// it signs only what Sign would. Its private half leaves it only through open.ExportPrivateKey. Every
// format prints its algorithm and recipient id, and nothing secret, as do String and GoString. A
// SigningKey copied by value into a field fmt cannot call a method of, an unexported field of the
// caller's struct, prints its fields instead, and its secrets are behind two pointers there, so fmt
// prints an address. A printer that follows pointers by reflection or unsafe, past what fmt does, can
// reach its secrets: never give a key to one. A SigningKey is not comparable, and is no map's key: two
// keys are one key when their PublicKey()s are equal. Its expanded keys stay in memory until the garbage
// collector frees them.
//
// A SigningKey is made by GenerateSigningKey, ImportSigningKey, IdentityAuthority or
// open.ImportPrivateKey, and used through a pointer. The zero SigningKey is no key, and an operation
// given it panics.
type SigningKey private.Signing

// GenerateSigningKey is a fresh ed25519+ml-dsa-65 key, for a signer with no key store of its own. Its
// signing seed is 32 bytes from crypto/rand, zeroised once the key is made from it, so the key's
// private half exists only in the key until open.ExportPrivateKey returns it.
//
// It never fails: crypto/rand stops the program rather than return bytes that are not random.
func GenerateSigningKey() *SigningKey {
	seed := make([]byte, private.SigningSeedSize)
	defer clear(seed)
	_, _ = rand.Read(seed)
	k, err := private.NewSigning(seed)
	if err != nil {
		panic("generateSigningKey: " + err.Error())
	}
	return (*SigningKey)(k)
}

// PublicKey is the key's public half.
func (k *SigningKey) PublicKey() sealdcrypto.PublicKey {
	return sealdcrypto.PublicKey((*private.Signing)(k).Public())
}

// Format writes the key's algorithm and recipient id, under every verb.
func (k SigningKey) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, k.String())
}

// String is the key's algorithm and recipient id, as Format writes them.
func (k SigningKey) String() string {
	return public.Key(k.PublicKey()).Describe("SigningKey")
}

// GoString is String, so %#v prints nothing secret either.
func (k SigningKey) GoString() string { return k.String() }

// Zeroise wipes the key once its holder is done with it, so a component that links sign and not open,
// such as one that holds the identity authority or the anchor where no key store does, can wipe the key
// GenerateSigningKey, ImportSigningKey or IdentityAuthority gave it. It overwrites the signing seed and
// Ed25519's key with zeros, and drops ML-DSA-65's, which crypto/mldsa gives no way to overwrite, so it
// lives until the garbage collector frees it: zeroising is best effort in a runtime with a garbage
// collector (the Crypto API, Keys).
//
// The key is then the zero key, and so is every copy of its handle: its PublicKey is the zero
// PublicKey, it prints as no key, and an operation given it panics, as one given the zero SigningKey
// does. Zeroising a key twice, or the zero key, does nothing. It is not safe to call while another
// goroutine signs with the key.
func (k *SigningKey) Zeroise() {
	if k != nil {
		(*private.Signing)(k).Zeroise()
	}
}

// ImportSigningKey is the vectors' importPrivateKey for an ed25519+ml-dsa-65 key, in sign: the key
// whose private half is seed, a 32-byte signing seed, as open.ImportPrivateKey imports it, so a
// component that links sign and not open, such as one that holds the anchor, loads the key it holds
// from its seed (the Crypto API, Parts).
//
// Where expected is not nil, the key's public half must equal it, algorithm and value, or the import is
// refused invalid-key: a caller holding the public key the seed should give passes it, so a seed that is
// not that key's, from storage, is never used as it. A seed that is not 32 bytes is refused invalid-key
// too.
//
// seed is the key itself, which ImportSigningKey copies and the caller zeroises. The key is a handle,
// and its private half leaves it only through open.ExportPrivateKey.
func ImportSigningKey(seed []byte, expected *sealdcrypto.PublicKey) (*SigningKey, error) {
	if len(seed) != private.SigningSeedSize {
		return nil, refusal.New(sealdcrypto.RefusalKindInvalidKey, "a private half of the wrong size")
	}
	k, err := private.NewSigning(seed)
	if err != nil {
		return nil, refusal.New(sealdcrypto.RefusalKindInvalidKey, "a private half that does not import")
	}
	key := (*SigningKey)(k)
	if expected != nil && key.PublicKey() != *expected {
		key.Zeroise()
		return nil, refusal.New(sealdcrypto.RefusalKindInvalidKey, "a private half that is not the key expected")
	}
	return key, nil
}

// AuthoritySeedSize is the authority seed's size, the environment's secret every identity authority is
// derived from.
const AuthoritySeedSize = 32

// IdentityAuthority is the vectors' identityAuthority: tenant's identity authority, the
// ed25519+ml-dsa-65 key whose signing seed is HKDF(authoritySeed, "seald/v1/identity-authority", tenant
// id), so a service holds every tenant's identity authority from one seed, and links no part but sign
// to do it (the Crypto API, Derivations and Parts).
//
// authoritySeed is the environment's secret, which IdentityAuthority never keeps and the caller
// zeroises; the signing seed it derives is zeroised once the key is made from it. Whoever holds the
// authority seed holds every tenant's identity authority, and so signs any card of any tenant: it is
// drawn from a CSPRNG, and kept where nothing but the service that signs with it reads it. One tenant's
// key tells nothing of another's, and the same seed and tenant always give the same key.
//
// An authority seed that is not AuthoritySeedSize bytes is a fault, and panics.
func IdentityAuthority(authoritySeed []byte, tenant sealdcrypto.TenantID) *SigningKey {
	if len(authoritySeed) != AuthoritySeedSize {
		panic("identityAuthority: an authority seed that is not 32 bytes")
	}
	seed := encoding.HKDF(authoritySeed, "seald/v1/identity-authority", private.SigningSeedSize, encoding.UUID(tenant))
	defer clear(seed)
	k, err := private.NewSigning(seed)
	if err != nil {
		panic("identityAuthority: " + err.Error())
	}
	return (*SigningKey)(k)
}

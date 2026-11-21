package seal

import (
	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/wrap"
)

// Wrap is secret sealed to to under context, as HPKE base mode, one message, with KEM X-Wing 0x647A,
// KDF HKDF-SHA256 0x0001 and AEAD AES-256-GCM 0x0002, info "seald/v1/wrap" and tuple(purpose, tenant
// id, …context) as its additional data. The wrap is enc ‖ ciphertext: 1120 bytes, then the secret's 32
// plus 16, 1168 in all. It opens only under the private half of to and the same context, so a secret
// wrapped for one purpose, object, epoch or tenant opens as no other.
//
// to is an x-wing key, or a device key, whose x-wing half the wrap is to. A key that only signs is
// refused invalid-key. No key of small order reaches it, as import refuses one. The encapsulation is
// drawn from crypto/rand, so two wraps of one secret differ.
//
// A wrap authenticates its context and its secret, and not who made it: anyone holding to can wrap to
// it, so a caller that needs to know who wrapped a secret checks a signature over it. secret is 32 bytes,
// as every secret of v1 is, and neither kept nor changed. A secret of another length, the zero
// PublicKey, a nil context, a pointer to a context, an empty locator in a content-key, domain-key or
// epoch-link context, an epoch below 1 in a domain-key, epoch-link or tokenisation-key context, and a
// linked epoch not below the one it is wrapped to, are faults, and panic, whatever else is given. A
// locator or a segment that is not well-formed Unicode is refused malformed.
func Wrap(to sealdcrypto.PublicKey, secret []byte, context sealdcrypto.WrapContext) ([]byte, error) {
	return wrap.Seal(to, secret, context)
}

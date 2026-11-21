package verify

import (
	"slices"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/public"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
)

// MaxIdentityAuthorities is the most identity authorities a tenant has at once: one, and two while the
// anchor rotates, when the new one signs every new card and a card the old one signed is still in use.
const MaxIdentityAuthorities = 2

// identityAuthorities is keys as a list of the tenant's identity authorities, as op takes it: each key
// once, a key given twice counting once, in the order first given. The zero PublicKey in keys, and a
// list of no key or of more than MaxIdentityAuthorities once each counts once, are the caller's mistake,
// and panic.
func identityAuthorities(op string, keys []sealdcrypto.PublicKey) []public.Key {
	list := make([]public.Key, 0, len(keys))
	for _, k := range keys {
		if pk := checked(op, k); !slices.Contains(list, pk) {
			list = append(list, pk)
		}
	}
	if len(list) == 0 || len(list) > MaxIdentityAuthorities {
		panic(op + ": not one or two identity authorities")
	}
	return list
}

// eachAnIdentityAuthority refuses invalid-key a key of authorities that is not ed25519+ml-dsa-65, the
// algorithm of every identity authority: a device key, which can sign, and an x-wing key among them.
func eachAnIdentityAuthority(authorities []public.Key) error {
	for _, k := range authorities {
		if sealdcrypto.PublicKey(k).Algorithm() != sealdcrypto.AlgorithmEd25519MLDSA65 {
			return refusal.New(sealdcrypto.RefusalKindInvalidKey, "an identity authority's key of another algorithm")
		}
	}
	return nil
}

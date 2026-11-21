// Package refoundingchallenge is a seal that wraps a re-founding's challenge, purpose
// refounding-challenge, and no other secret. A component that may seal refounding-challenge alone
// imports this package and never seal, so it keeps to that purpose by what it links, which
// parts_test.go holds: it links no part but the module root and internal/wrap's sealing, and nothing
// that signs, unwraps or decrypts.
package refoundingchallenge

import (
	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/wrap"
)

// ChallengeSize is a re-founding's challenge: 32 random bytes.
const ChallengeSize = wrap.SecretSize

// Wrap is challenge wrapped to to, the tenant's backup key, under context, as seal.Wrap wraps it, 1168
// bytes. It opens only under the backup key and the same context, so only whoever holds the recovery
// phrase opens it.
//
// context is a WrapContextRefoundingChallenge, so no other purpose's context compiles as one. A key that
// only signs is refused invalid-key. challenge is 32 bytes from crypto/rand, neither kept nor changed:
// keep your own copy to compare, in constant time, with what comes back.
//
// A challenge that is not 32 bytes and the zero PublicKey are faults, and panic.
func Wrap(to sealdcrypto.PublicKey, challenge []byte, context sealdcrypto.WrapContextRefoundingChallenge) ([]byte, error) {
	return wrap.Seal(to, challenge, context)
}

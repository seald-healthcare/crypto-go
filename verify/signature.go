package verify

import (
	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
	signatures "github.com/seald-healthcare/crypto-go/internal/signature"
)

// SignatureSize is a signature's size: Ed25519's 64 bytes, then ML-DSA-65's 3309.
const SignatureSize = signatures.Size

var unknownLabel = refusal.New(sealdcrypto.RefusalKindUnsupported, "a label v1 does not have")

// VerifySignature is the vectors' verifySignature: whether signature is key's over
// tuple("seald/v1/signature", label, payload). It is true only when signature is exactly 3373 bytes and
// both halves verify, and both are always checked, so forging one takes breaking both Ed25519 and
// ML-DSA-65.
//
// The label is checked first, before the key and either half: one v1 does not have, as one read from
// a wire may be, is refused unsupported, and the answer is then false. So a label this library does not
// know is told apart from a signature that does not verify, and a caller that drops the error still
// holds false. Under a label v1 has, the error is nil and the answer is the verdict.
//
// Ed25519 is checked as RFC 8032, section 5.1.7 sets, and never as ZIP 215: S below the group order,
// R the canonical encoding of a point and the cofactorless equation, as crypto/ed25519 checks them,
// under a key ImportPublicKey checked. ML-DSA-65 is FIPS 204's ML-DSA.Verify, with the empty context.
//
// A key that cannot sign, an x-wing key, verifies nothing, and gives false with no error. A device key
// verifies as its ed25519+ml-dsa-65 part. A true answer says who signed payload under label and nothing
// else: the caller checks that key is the one the flow expects, and that payload is what it goes on to
// trust.
//
// The zero PublicKey is a fault, and panics.
func VerifySignature(key sealdcrypto.PublicKey, label sealdcrypto.Label, payload, signature []byte) (bool, error) {
	k := checked("verifySignature", key)
	message, ok := signatures.Message(label, payload)
	if !ok {
		return false, unknownLabel
	}
	return signatures.Verify(k, message, signature), nil
}

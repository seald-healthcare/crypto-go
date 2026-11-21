package verify

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	bodies "github.com/seald-healthcare/crypto-go/internal/body"
	"github.com/seald-healthcare/crypto-go/internal/canonical"
	"github.com/seald-healthcare/crypto-go/internal/encoding"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
	"github.com/seald-healthcare/crypto-go/internal/signature"
)

// SaltSize is an invitation's salt: 32 random bytes the inviter's device draws.
const SaltSize = 32

// PersonHash is the vectors' personHash: SHA-256 over the canonical JSON of tenant_id, iss and sub, how
// a card and a service name a person of a tenant without holding their subject. tenant_id is the
// tenant's UUID as RFC 9562's text in lower case, and iss and sub are the identity provider's, exactly
// as given.
//
// Nothing keys it, so a subject that is an email can be confirmed by someone who guesses it: it hides
// a subject from a reader who does not already suspect it, and no more. It refuses malformed where iss
// or sub is not well-formed Unicode.
func PersonHash(tenant sealdcrypto.TenantID, person sealdcrypto.Person) ([]byte, error) {
	b, err := canonical.JSON(map[string]any{"tenant_id": tenant.String(), "iss": person.Iss, "sub": person.Sub})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// SecretHash is the vectors' secretHash over a secret's bytes: SHA-256 over the bytes of a setup code,
// a guest code or an enrolment secret, which a server keeps in place of the secret. A secret that
// travels as text, a session secret or a service's link key, is hashed through TextSecretHash alone,
// over its text, never here over bytes the text decodes to: a session secret's 256 bits given here hash
// to a value no DPoP proof carries and no server keeps.
//
// It hides only a secret drawn with enough entropy to resist guessing: a hash of a short or chosen
// secret is as good as the secret to whoever can guess it.
func SecretHash(secret []byte) []byte {
	sum := sha256.Sum256(secret)
	return sum[:]
}

// TextSecretHash is the vectors' secretHash over a secret that travels as text: SHA-256 over the
// text's UTF-8, exactly as given, of a session secret or a service's link key. It refuses malformed
// where secret is not well-formed Unicode, as every text a caller gives is refused.
//
// A session secret is hashed as its text, the base64url without padding of its 256 random bits exactly
// as it travels in Authorization under the DPoP scheme, never as the 32 bytes that text encodes. That
// is the hash RFC 9449, section 4.2, lays out for a DPoP proof's ath, the SHA-256 of the access token's
// ASCII, which ath carries as base64url without padding, and the hash a server keeps in place of the
// secret, so the hash it kept, the hash of the secret a request carries and the proof's ath are one
// value. A server that draws the secret hashes the text it returns, never the bytes it drew.
//
// It checks nothing of the text beyond its Unicode, as ath hashes the token as sent: a text that is not
// a session secret's hashes to a value no session keeps. A session secret's hash travels in every
// proof's ath, so it is no secret and proves nothing alone. It hides only a secret drawn with enough
// entropy to resist guessing, as SecretHash's does.
func TextSecretHash(secret string) ([]byte, error) {
	b, ok := encoding.Text(secret)
	if !ok {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "text that is not well-formed Unicode")
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// EmailHash is the vectors' emailHash: HMAC-SHA-256(salt, tuple("seald/v1/email", tenant, email)), the
// email's UTF-8 with A to Z lowered to a to z and nothing else changed, under the invitation's salt.
// Without the salt, which stays with the invitation, a service handed only the hash cannot test it
// against a guessed address.
//
// Only ASCII's upper case is lowered, so an address that differs outside ASCII, such as in "É", hashes
// as another address. It refuses malformed where email is not well-formed Unicode. A salt that is not
// SaltSize bytes is a fault, and panics: a caller holding a salt from a wire checks its length first.
func EmailHash(salt []byte, tenant sealdcrypto.TenantID, email string) ([]byte, error) {
	if len(salt) != SaltSize {
		panic("emailHash: a salt that is not 32 bytes")
	}
	b, err := lowered(email)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(encoding.Tuple([]byte("seald/v1/email"), encoding.UUID(tenant), b))
	return mac.Sum(nil), nil
}

// FoundingEmailHash is the vectors' foundingEmailHash: SHA-256 over the email's UTF-8, with A to Z
// lowered to a to z and nothing else changed, the email a founding or re-founding token binds, as the
// service that issues tokens answers it when the token is checked.
//
// Nothing keys it, so it hides an address from no one who guesses it: anyone who suspects an address
// confirms it against the hash. It is for comparing the email a token binds, and never in place of an
// email hash, which an invitation's salt keys. Only ASCII's upper case is lowered, as EmailHash lowers
// it, so an address that differs outside ASCII hashes as another address. It refuses malformed where
// email is not well-formed Unicode.
func FoundingEmailHash(email string) ([]byte, error) {
	b, err := lowered(email)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// lowered is email's UTF-8 with A to Z lowered to a to z and nothing else changed, as an email hash and
// a founding email hash lower it, refused malformed where email is not well-formed Unicode.
func lowered(email string) ([]byte, error) {
	b, ok := encoding.Text(email)
	if !ok {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "text that is not well-formed Unicode")
	}
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return b, nil
}

// JSONHash is the vectors' jsonHash: SHA-256 over the canonical JSON of value, such as an event's
// digest or a policy version's hash. It refuses what CanonicalJSON refuses.
func JSONHash(value sealdcrypto.JSON) ([]byte, error) {
	b, err := canonical.JSON(value)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// WitnessHash is the vectors' witnessHash: SHA-256 over a folder index's whole container as the writer
// put it, which a commit carries as index_hash and the freshness witness rises to. The writer hashes the
// bytes it puts, and a verifier of the commit takes the hash from the commit and hashes no index
// itself. It checks nothing of the bytes: the container is opened and checked apart.
func WitnessHash(container []byte) []byte {
	sum := sha256.Sum256(container)
	return sum[:]
}

// TokenisationKeySize is a tokenisation key's size, one epoch of the tenant's key, and
// TokenisationCheckSize its check's.
const (
	TokenisationKeySize   = 32
	TokenisationCheckSize = sha256.Size
)

// TokenisationCheck is the vectors' tokenisationCheck: SHA-256(tuple("seald/v1/tokenisation-check",
// u64be(epoch), key)), the check of one epoch of the tenant's tokenisation key, 32 bytes. The client
// that mints the epoch sends it, the server keeps it, and every device that unwraps the epoch checks
// the key it opened against it with CheckTokenisationKey.
//
// It reveals nothing of a 256-bit random key, and hashing the key is all it does: it never keeps the key,
// and clears the bytes it hashed. It is no proof of who minted the key, since anyone holding the key
// makes its check: it shows only that every device holds the one key the check was made from. A key that
// is not TokenisationKeySize bytes, and an epoch below 1, are faults, and panic: no key of another
// length is a tokenisation key, and the founding mints epoch 1, so no epoch is 0.
func TokenisationCheck(epoch uint64, key []byte) []byte {
	if len(key) != TokenisationKeySize {
		panic("tokenisationCheck: a tokenisation key that is not 32 bytes")
	}
	if epoch < 1 {
		panic("tokenisationCheck: an epoch below 1")
	}
	m := encoding.Tuple([]byte("seald/v1/tokenisation-check"), encoding.U64(epoch), key)
	defer clear(m)
	sum := sha256.Sum256(m)
	return sum[:]
}

var otherTokenisationKey = refusal.New(sealdcrypto.RefusalKindAuthenticationFailed, "a tokenisation key whose check differs")

// CheckTokenisationKey is the vectors' checkTokenisationKey: nil where check is the tokenisation check
// of key at epoch, and refused authentication-failed where it differs, a check of another length among
// them, which differs from every key's. It compares in constant time, and the refusal says nothing of
// the key or the check.
//
// A device calls it on every epoch of the tokenisation key it unwraps, with the epoch it asked for and
// the check the server kept, before it uses the key, so a key wrapped to it that is not the one every
// other device holds makes no ref. A key that is not TokenisationKeySize bytes, and an epoch below 1,
// are faults, and panic, as TokenisationCheck's are: an unwrapped key is always 32 bytes, and the caller
// gives the epoch it asked for.
func CheckTokenisationKey(epoch uint64, key, check []byte) error {
	if subtle.ConstantTimeCompare(TokenisationCheck(epoch, key), check) != 1 {
		return otherTokenisationKey
	}
	return nil
}

// UnlockChallenge is the vectors' unlockChallenge: SHA-256 over tuple("seald/v1/signature", "unlock",
// body), the message an unlock body is signed as, the challenge a passkey asserts over in a fresh
// unlock, so a passkey's assertion and the device key's signature commit to the same body. The body is
// read first as ReadUnlockBody reads it, and one it refuses is refused alike, malformed, so no touch
// commits to a body a reader refuses.
//
// The challenge commits to the body it is given. The client gives the bytes it rebuilt from what it
// asked before the touch and compared with the server's, never the server's bytes unchecked.
func UnlockChallenge(body []byte) ([]byte, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return nil, err
	}
	if _, err := bodies.ReadUnlock(v); err != nil {
		return nil, err
	}
	return challengeOf(sealdcrypto.LabelUnlock, body), nil
}

// AppAttestChallenge is the vectors' appAttestChallenge: SHA-256 over tuple("seald/v1/signature",
// "session", body), the clientDataHash App Attest attests or asserts over at a session's opening on iOS,
// so the attestation commits to the tenant, nonce and session key the device key signs.
//
// The body is read first as ReadSessionBody reads an opening, and one it refuses is refused alike,
// malformed. Only an opening is attested, so a resume, or any other purpose, is refused malformed.
//
// It checks nothing of who signed the body. The client takes it over the bytes it signs, and the
// server over the bytes whose signature it verified, never over bytes it was handed unchecked.
func AppAttestChallenge(body []byte) ([]byte, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return nil, err
	}
	if _, err := bodies.ReadSessionOpening(v); err != nil {
		return nil, err
	}
	return challengeOf(sealdcrypto.LabelSession, body), nil
}

// PasskeyChallengeEnrolment is the vectors' passkeyChallenge under enrolment: SHA-256 over
// tuple("seald/v1/signature", "enrolment", body), the message an enrolment request is signed as. A web
// client whose device key a passkey seals sends, beside its enrolment request, a new passkey's WebAuthn
// registration or an assertion by a passkey the person already holds, whose challenge is this one, so
// the ceremony commits to the request the device key signed and no other.
//
// The body is read first as ReadEnrolmentRequestBody reads it, and one it refuses is refused alike,
// malformed or invalid-key, so no ceremony commits to a body a reader refuses. It takes an enrolment
// request alone, the body a new device sends beside its passkey's ceremony: a rotation request, the
// other body a key signs under enrolment, is ReadRotationRequestBody's, and since no rotation binds a
// passkey, given here it is refused malformed, as ReadEnrolmentRequestBody refuses it.
//
// The challenge commits to the bytes it is given and checks nothing of who signed them: the server
// verifies the device key's signature over these very bytes, and the ceremony against this challenge,
// as a relying party does. The client takes it over the bytes it signs, never over bytes it was handed.
func PasskeyChallengeEnrolment(body []byte) ([]byte, error) {
	if _, err := ReadEnrolmentRequestBody(body); err != nil {
		return nil, err
	}
	return challengeOf(sealdcrypto.LabelEnrolment, body), nil
}

// PasskeyChallengePasskey is the vectors' passkeyChallenge under passkey: SHA-256 over
// tuple("seald/v1/signature", "passkey", body), the message a passkey body is signed as, the challenge of
// the WebAuthn registration of a new passkey, under register, or of the assertion by the passkey a
// device key is sealed under, under seal, so the ceremony commits to the body the device key signed and
// no other.
//
// The body is read first as ReadPasskeyBody reads it, and one it refuses is refused alike, malformed, so
// no ceremony commits to a body a reader refuses.
//
// The challenge commits to the bytes it is given and checks nothing of who signed them: the server
// verifies the device key's signature over these very bytes, and the ceremony against this challenge,
// as a relying party does. The client takes it over the bytes it signs, never over bytes it was handed.
func PasskeyChallengePasskey(body []byte) ([]byte, error) {
	if _, err := ReadPasskeyBody(body); err != nil {
		return nil, err
	}
	return challengeOf(sealdcrypto.LabelPasskey, body), nil
}

// challengeOf is SHA-256 over the message body is signed as under label, a label v1 has, of a body its
// reader has read.
func challengeOf(label sealdcrypto.Label, body []byte) []byte {
	m, _ := signature.Message(label, body)
	sum := sha256.Sum256(m)
	return sum[:]
}

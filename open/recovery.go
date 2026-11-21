package open

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/bip39"
	"github.com/seald-healthcare/crypto-go/internal/private"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
)

// RecoveryPhraseWords is the number of words in a recovery phrase.
const RecoveryPhraseWords = 24

// FingerprintSize is the backup key's fingerprint's size: its key digest.
const FingerprintSize = sha256.Size

// EncodeRecoveryPhrase is the recovery phrase of key, the backup key: its X-Wing seed as 24 BIP-39
// English words in lower case, separated by one space, in a new slice.
//
// Whoever holds the phrase holds the key: show it to the Owner once, then Zeroise it, and never log,
// store or send it. A nil key, or the zero key, is a fault, and panics.
func EncodeRecoveryPhrase(key *ReceivingKey) []byte {
	if key == nil || (*private.Receiving)(key).Public().IsZero() {
		panic("encodeRecoveryPhrase: no key")
	}
	seed := (*private.Receiving)(key).Seed()
	defer clear(seed)
	return bip39.Phrase(seed)
}

// CheckRecoveryPhrase is the backup key phrase holds, once its key digest is fingerprint, the backup
// key's fingerprint the caller pinned when the key was registered, never one sent beside the phrase.
//
// It refuses malformed a phrase of other than 24 words, a word outside BIP-39's English list, and any
// other text: a capital, and spacing other than one space between words, among them. Taking what a
// person types into that form is the caller's. It refuses phrase-mismatch a phrase whose checksum fails,
// and one whose key's digest is not fingerprint, whose key is zeroised and never returned.
//
// phrase is the caller's to zeroise, and the key the caller's to Zeroise once used. A fingerprint that is
// not FingerprintSize bytes is a fault, and panics before the phrase is read.
func CheckRecoveryPhrase(phrase, fingerprint []byte) (*ReceivingKey, error) {
	if len(fingerprint) != FingerprintSize {
		panic("checkRecoveryPhrase: a fingerprint that is not 32 bytes")
	}
	seed, err := decodeRecoveryPhrase(phrase)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	k, err := private.NewReceiving(seed)
	if err != nil {
		panic("checkRecoveryPhrase: " + err.Error())
	}
	if digest := k.Public().Digest(); subtle.ConstantTimeCompare(digest[:], fingerprint) != 1 {
		k.Zeroise()
		return nil, refusal.New(sealdcrypto.RefusalKindPhraseMismatch, "a recovery phrase of another key")
	}
	return (*ReceivingKey)(k), nil
}

// decodeRecoveryPhrase is the seed phrase writes, unchecked against any fingerprint, which is why it is
// not exported: a seed is used only once CheckRecoveryPhrase has checked it.
func decodeRecoveryPhrase(phrase []byte) ([]byte, error) {
	seed, err := bip39.ParsePhrase(phrase, RecoveryPhraseWords)
	switch {
	case errors.Is(err, bip39.ErrForm):
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "a recovery phrase that is not 24 words in lower case, separated by one space")
	case errors.Is(err, bip39.ErrWord):
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "a recovery phrase with a word outside its list")
	case errors.Is(err, bip39.ErrChecksum):
		return nil, refusal.New(sealdcrypto.RefusalKindPhraseMismatch, "a recovery phrase whose checksum fails")
	case err != nil:
		panic("decodeRecoveryPhrase: " + err.Error())
	}
	return seed, nil
}

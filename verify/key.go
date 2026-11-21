package verify

import (
	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/bip39"
	"github.com/seald-healthcare/crypto-go/internal/public"
)

// checked is key's value, where key is a key. The zero PublicKey is a fault, and panics.
func checked(op string, key sealdcrypto.PublicKey) public.Key {
	k := public.Key(key)
	if k.IsZero() {
		panic(op + ": no key")
	}
	return k
}

// KeyExport is the vectors' keyExport: tuple("seald/v1/public-key", algorithm, value), the bytes that
// name key in its digest, a tuple and a signed message. Two keys have one export only when they are one
// key.
//
// The zero PublicKey is a fault, and panics.
func KeyExport(key sealdcrypto.PublicKey) []byte {
	return checked("keyExport", key).Export()
}

// KeyDigest is the vectors' keyDigest: SHA-256 over the key's export, 32 bytes. It is the backup key's
// fingerprint and the anchor's id. A digest names a key and never proves one: a caller holding one
// checks the key it names against it.
//
// The zero PublicKey is a fault, and panics.
func KeyDigest(key sealdcrypto.PublicKey) []byte {
	digest := checked("keyDigest", key).Digest()
	return digest[:]
}

// RecipientID is the vectors' recipientId: the first 16 bytes of the key digest, which names the key in
// a card, a wrap and a share. Like the digest, it names a key and never proves one.
//
// The zero PublicKey is a fault, and panics.
func RecipientID(key sealdcrypto.PublicKey) sealdcrypto.RecipientID {
	return checked("recipientId", key).RecipientID()
}

// FingerprintWords is the vectors' fingerprintWords: the key's recipient id as 12 BIP-39 English words,
// for two people to read aloud and compare. Its 128 bits are the recipient id's, and a key made to
// share them takes a second preimage of SHA-256's first 16 bytes.
//
// The zero PublicKey is a fault, and panics.
func FingerprintWords(key sealdcrypto.PublicKey) []string {
	id := checked("fingerprintWords", key).RecipientID()
	return bip39.Words(id[:])
}

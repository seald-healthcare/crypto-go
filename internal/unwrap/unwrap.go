// Package unwrap opens wraps for open alone: under a key held here through crypto/hpke, or with a
// shared secret a receiver held elsewhere gives, through an RFC 9180 key schedule built here, since
// crypto/hpke takes no shared secret. It decrypts, so no other part links it.
package unwrap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/fips140"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/keyimport"
	"github.com/seald-healthcare/crypto-go/internal/private"
	"github.com/seald-healthcare/crypto-go/internal/public"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
	"github.com/seald-healthcare/crypto-go/internal/wrap"
	"github.com/seald-healthcare/crypto-go/internal/xwing"
)

// Open opens wrapped to key under context and returns the secret in a new slice for the caller to
// zeroise. A wrap is made to a public key, so its length is checked here, before it is decrypted.
func Open(op string, key hpke.PrivateKey, wrapped []byte, context sealdcrypto.WrapContext) ([]byte, error) {
	aad, err := wrap.AAD(op, context)
	if err != nil {
		return nil, err
	}
	if len(wrapped) != wrap.Size {
		return nil, otherLength
	}
	return open(key, []byte(wrap.Info), wrapped[:wrap.EncSize], wrapped[wrap.EncSize:], aad)
}

var otherLength = refusal.New(sealdcrypto.RefusalKindAuthenticationFailed, "a wrap of another length than 1168 bytes")

// open is HPKE's single-shot open at any info, so RFC 9180's vectors run through it.
func open(key hpke.PrivateKey, info, enc, ciphertext, aad []byte) ([]byte, error) {
	kdf, aead := wrap.Suite()
	r, err := hpke.NewRecipient(enc, key, kdf, aead, info)
	if err != nil {
		return nil, notOpened
	}
	secret, err := r.Open(aad, ciphertext)
	if err != nil {
		return nil, notOpened
	}
	return secret, nil
}

var notOpened = refusal.New(sealdcrypto.RefusalKindAuthenticationFailed, "a wrap that does not open under the key and context asked for")

var (
	smallOrder    = refusal.New(sealdcrypto.RefusalKindAuthenticationFailed, "a wrap whose X25519 ephemeral is of small order")
	notAnEnc      = refusal.New(sealdcrypto.RefusalKindAuthenticationFailed, "an encapsulation that is not 1120 bytes")
	notASharedKey = refusal.New(sealdcrypto.RefusalKindAuthenticationFailed, "a shared secret from the receiver that is not 32 bytes")
	cannotReceive = refusal.New(sealdcrypto.RefusalKindInvalidKey, "a receiver whose key cannot receive")
)

// Decapsulate returns X-Wing's shared secret of enc under key (draft -11) in a new slice for the caller
// to zeroise. It is a fault under FIPS 140-only mode, which refuses X25519 outside crypto/hpke.
func Decapsulate(key *private.Receiving, enc []byte) ([]byte, error) {
	checkNotFIPSOnly("decapsulate")
	if len(enc) != wrap.EncSize {
		return nil, notAnEnc
	}
	m, x := key.XWing()
	ctM, ctX := enc[:xwing.MLKEMCiphertextSize], enc[xwing.MLKEMCiphertextSize:]
	ssM, err := m.Decapsulate(ctM)
	if err != nil {
		// ML-KEM-768 decapsulates every ciphertext of its length, rejecting implicitly.
		panic("decapsulate: " + err.Error())
	}
	defer clear(ssM)
	p, err := ecdh.X25519().NewPublicKey(ctX)
	if err != nil {
		return nil, smallOrder
	}
	ssX, err := x.ECDH(p)
	if err != nil {
		// crypto/ecdh refuses an all-zero shared secret: an ephemeral of small order.
		return nil, smallOrder
	}
	defer clear(ssX)
	return xwing.Combine(ssM, ssX, ctX, x.PublicKey().Bytes()), nil
}

// OpenWith is Open with the shared secret decapsulate gives for the wrap's enc. decapsulate is asked
// only once every check of the wrap's own bytes has passed, and its error is returned unchanged.
func OpenWith(op string, key public.Key, wrapped []byte, context sealdcrypto.WrapContext, decapsulate func(enc []byte) ([]byte, error)) ([]byte, error) {
	checkNotFIPSOnly(op)
	aad, err := wrap.AAD(op, context)
	if err != nil {
		return nil, err
	}
	if a := key.Algorithm(); a != public.XWing && a != public.XWingEd25519MLDSA65 {
		return nil, cannotReceive
	}
	if len(wrapped) != wrap.Size {
		return nil, otherLength
	}
	enc := bytes.Clone(wrapped[:wrap.EncSize])
	if keyimport.X25519SmallOrder(enc[xwing.MLKEMCiphertextSize:]) {
		return nil, smallOrder
	}
	shared, err := decapsulate(enc)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	if len(shared) != xwing.SharedSecretSize {
		return nil, notASharedKey
	}
	return openShared(suiteID(), shared, []byte(wrap.Info), wrapped[wrap.EncSize:], aad)
}

// checkNotFIPSOnly panics under FIPS 140-only mode, where X25519 and AES-GCM under a set nonce fail: a
// wrap refused for that alone would read as one that does not open.
func checkNotFIPSOnly(op string) {
	if fips140.Enforced() {
		panic(op + ": FIPS 140-only mode, which refuses X25519 outside crypto/hpke and AES-GCM under a set nonce")
	}
}

// suiteID is RFC 9180's suite_id (section 5.1) for a wrap's suite.
func suiteID() []byte {
	kdf, aead := wrap.Suite()
	s := []byte("HPKE")
	s = binary.BigEndian.AppendUint16(s, xwing.KEM().ID())
	s = binary.BigEndian.AppendUint16(s, kdf.ID())
	return binary.BigEndian.AppendUint16(s, aead.ID())
}

// The sizes of RFC 9180's section 7.3 for AES-256-GCM: Nk and Nn.
const (
	keySize   = 32
	nonceSize = 12
)

// openShared is RFC 9180's single-shot base-mode open from a shared secret (sections 5.1 and 5.2). The
// key schedule's secrets are zeroised once used.
func openShared(suite, sharedSecret, info, ciphertext, aad []byte) ([]byte, error) {
	key, nonce := keySchedule(suite, sharedSecret, info)
	defer clear(key)
	defer clear(nonce)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("unwrap: " + err.Error())
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic("unwrap: " + err.Error())
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, notOpened
	}
	return plaintext, nil
}

// keySchedule is RFC 9180's KeyScheduleR in base mode: the AEAD's key and base_nonce, each a new slice
// for the caller to zeroise.
func keySchedule(suite, sharedSecret, info []byte) (key, baseNonce []byte) {
	pskIDHash := labeledExtract(suite, nil, "psk_id_hash", nil)
	infoHash := labeledExtract(suite, nil, "info_hash", info)
	scheduleContext := append(append([]byte{0x00}, pskIDHash...), infoHash...)
	secret := labeledExtract(suite, sharedSecret, "secret", nil)
	defer clear(secret)
	return labeledExpand(suite, secret, "key", scheduleContext, keySize), labeledExpand(suite, secret, "base_nonce", scheduleContext, nonceSize)
}

// labeledExtract is RFC 9180's LabeledExtract (section 4).
func labeledExtract(suite, salt []byte, label string, ikm []byte) []byte {
	labeled := bytes.Join([][]byte{[]byte("HPKE-v1"), suite, []byte(label), ikm}, nil)
	defer clear(labeled)
	prk, err := hkdf.Extract(sha256.New, labeled, salt)
	if err != nil {
		panic("unwrap: " + err.Error())
	}
	return prk
}

// labeledExpand is RFC 9180's LabeledExpand (section 4).
func labeledExpand(suite, prk []byte, label string, info []byte, length int) []byte {
	labeled := bytes.Join([][]byte{binary.BigEndian.AppendUint16(nil, uint16(length)), []byte("HPKE-v1"), suite, []byte(label), info}, nil) //nolint:gosec // length is Nk or Nn
	out, err := hkdf.Expand(sha256.New, prk, string(labeled), length)
	if err != nil {
		panic("unwrap: " + err.Error())
	}
	return out
}

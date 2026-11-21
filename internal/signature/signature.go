// Package signature is signing's shared part for sign and verify: the message a signature is made over,
// the labels v1 has, and verifying both halves.
package signature

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"encoding/binary"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/encoding"
	"github.com/seald-healthcare/crypto-go/internal/public"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
)

// Size is a signature's: Ed25519's 64 bytes, then ML-DSA-65's 3309.
const Size = ed25519.SignatureSize + mldsa.MLDSA65SignatureSize

const domain = "seald/v1/signature"

// labels is every label of the contract's Labels table.
var labels = map[sealdcrypto.Label]bool{
	sealdcrypto.LabelSession:           true,
	sealdcrypto.LabelEnrolment:         true,
	sealdcrypto.LabelDeviceCall:        true,
	sealdcrypto.LabelApproval:          true,
	sealdcrypto.LabelRotation:          true,
	sealdcrypto.LabelInvitation:        true,
	sealdcrypto.LabelAccount:           true,
	sealdcrypto.LabelEnvelope:          true,
	sealdcrypto.LabelCommit:            true,
	sealdcrypto.LabelShare:             true,
	sealdcrypto.LabelOwnership:         true,
	sealdcrypto.LabelMove:              true,
	sealdcrypto.LabelBackfill:          true,
	sealdcrypto.LabelJoin:              true,
	sealdcrypto.LabelEpoch:             true,
	sealdcrypto.LabelManifest:          true,
	sealdcrypto.LabelOffline:           true,
	sealdcrypto.LabelRole:              true,
	sealdcrypto.LabelPolicy:            true,
	sealdcrypto.LabelGrant:             true,
	sealdcrypto.LabelAgent:             true,
	sealdcrypto.LabelAgentState:        true,
	sealdcrypto.LabelDelegation:        true,
	sealdcrypto.LabelVendor:            true,
	sealdcrypto.LabelRevocation:        true,
	sealdcrypto.LabelPersonState:       true,
	sealdcrypto.LabelPasskey:           true,
	sealdcrypto.LabelUnlock:            true,
	sealdcrypto.LabelRecovery:          true,
	sealdcrypto.LabelRegistration:      true,
	sealdcrypto.LabelCard:              true,
	sealdcrypto.LabelBackupKey:         true,
	sealdcrypto.LabelIdentityAuthority: true,
}

// Known is whether label is one v1 has.
func Known(label sealdcrypto.Label) bool {
	return labels[label]
}

// Certifies is whether label is one a certificate is made under: identity-authority, by the anchor,
// and card, by the identity authority.
func Certifies(label sealdcrypto.Label) bool {
	return label == sealdcrypto.LabelIdentityAuthority || label == sealdcrypto.LabelCard
}

// Message is tuple("seald/v1/signature", label, payload), and false for a label v1 does not have.
func Message(label sealdcrypto.Label, payload []byte) ([]byte, bool) {
	if !Known(label) {
		return nil, false
	}
	return encoding.Tuple([]byte(domain), []byte(label), payload), true
}

// CheckMessage refuses a message that is not tuple("seald/v1/signature", label, payload) under a label
// v1 has: malformed where it is not such a tuple, and unsupported where its label is not one v1 has.
// It is what a local key checks before it signs, so that no key this library holds signs without a
// label.
func CheckMessage(message []byte) error {
	parts, ok := split(message)
	if !ok || len(parts) != 3 || string(parts[0]) != domain {
		return refusal.New(sealdcrypto.RefusalKindMalformed, "a message that is not a signature's")
	}
	if !Known(sealdcrypto.Label(parts[1])) {
		return refusal.New(sealdcrypto.RefusalKindUnsupported, "a label v1 does not have")
	}
	return nil
}

// A Certificate is a certificate's parts, as SplitCertificate reads them.
type Certificate struct {
	// Message is tuple(Domain, Label, Body), as received.
	Message []byte
	// Domain is the message's first part, "seald/v1/signature" in a certificate any key signed.
	Domain []byte
	Label  sealdcrypto.Label
	Body   []byte
	// Signature is the rest, Size bytes.
	Signature []byte
}

// SplitCertificate reads certificate = tuple(domain, label, body) ‖ signature, refusing malformed
// what does not parse so: three parts, then exactly Size bytes. It checks neither the domain, the label
// nor the signature, since a verifier checks the bytes as received before it reads them
// (the Crypto API, Certificates), and its parts share certificate's bytes.
func SplitCertificate(certificate []byte) (Certificate, error) {
	parts, rest, ok := read(certificate, 3)
	if !ok || len(rest) != Size {
		return Certificate{}, refusal.New(sealdcrypto.RefusalKindMalformed, "bytes that are not a certificate")
	}
	n := len(certificate) - Size
	return Certificate{Message: certificate[:n:n], Domain: parts[0], Label: sealdcrypto.Label(parts[1]), Body: parts[2], Signature: certificate[n:]}, nil
}

// Signed is whether c's message begins "seald/v1/signature", as every message a Seald key signs does:
// one that does not carries no Seald signature, whatever its bytes.
func (c Certificate) Signed() bool {
	return string(c.Domain) == domain
}

// split reads a tuple's parts, and false where b is not one, whole.
func split(b []byte) ([][]byte, bool) {
	var parts [][]byte
	for len(b) > 0 {
		p, rest, ok := read(b, 1)
		if !ok {
			return nil, false
		}
		parts = append(parts, p[0])
		b = rest
	}
	return parts, true
}

// read reads count parts of a tuple from the front of b, and the bytes after them, and false where b
// does not begin with count parts.
func read(b []byte, count int) (parts [][]byte, rest []byte, ok bool) {
	for range count {
		if len(b) < 4 {
			return nil, nil, false
		}
		n := binary.BigEndian.Uint32(b)
		b = b[4:]
		if uint64(n) > uint64(len(b)) {
			return nil, nil, false
		}
		parts = append(parts, b[:n:n])
		b = b[n:]
	}
	return parts, b, true
}

// Verify is whether signature, over message, verifies under key: exactly Size bytes, and both halves
// verifying. Both are always checked. A key that cannot sign verifies nothing, and a device key
// verifies as its ed25519+ml-dsa-65 part. Ed25519 is crypto/ed25519's, which is RFC 8032, section
// 5.1.7: S below the group order, R compared with the canonical encoding of the point it computes, so
// a non-canonical R never verifies, and the cofactorless equation. The key passed import's checks, or
// was derived from a private half.
func Verify(key public.Key, message, signature []byte) bool {
	value := key.Value()
	switch key.Algorithm() {
	case public.Ed25519MLDSA65:
	case public.XWingEd25519MLDSA65:
		value = value[public.XWingSize:]
	default:
		return false
	}
	if len(signature) != Size {
		return false
	}
	edOK := ed25519.VerifyWithOptions(ed25519.PublicKey(value[:ed25519.PublicKeySize]), message, signature[:ed25519.SignatureSize], &ed25519.Options{}) == nil
	mlOK := false
	if pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), value[ed25519.PublicKeySize:]); err == nil {
		mlOK = mldsa.Verify(pk, message, signature[ed25519.SignatureSize:], &mldsa.Options{}) == nil
	}
	return edOK && mlOK
}

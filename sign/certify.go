package sign

import (
	"context"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/body"
	"github.com/seald-healthcare/crypto-go/internal/canonical"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
	"github.com/seald-healthcare/crypto-go/internal/signature"
)

// Certify is the vectors' certify: the certificate over body's canonical JSON,
// tuple("seald/v1/signature", label, body) ‖ signature, the message and then signer's signature over
// it. A verifier checks it with verify.ReadCertificate, which verifies the bytes as received before it
// reads the body.
//
// label is sealdcrypto.LabelIdentityAuthority, for the anchor certifying an identity authority, or
// sealdcrypto.LabelCard, for the identity authority certifying a card. Any other is refused
// unsupported, so no signer makes a certificate under a label that is not a certificate's, once the
// body is found to have canonical JSON: a body with none is a fault whatever the label.
//
// The body is then checked as a reader checks it, so that no certificate is signed that a reader
// refuses: first that it has canonical JSON, as verify.CanonicalJSON writes it, which a body holding a
// fraction, an integer of 2^53 or more, text that is not well-formed Unicode or arrays nested past 64
// has not; then, read back from that JSON, that it holds exactly its label's members, each in its one
// written form, as verify.VerifyIdentityAuthority and verify.VerifyCard read them, and that its
// public_key imports as verify.ImportPublicKey imports it and is of the label's algorithm; and for a
// card, that its recipient_id is that of its public_key and its valid_until is after its issued_at, so
// its window holds an instant. A body that fails any of these is the caller's mistake, a fault, and
// panics before the signer is called, whatever the signer. What Certify cannot check is the caller's:
// that the tenant, person and key are the ones the flow certifies, and that the card's window is the
// one it means.
//
// Everything after is as Sign: invalid-key for a signer whose key cannot sign, an error of the
// signer's own returned unchanged, and what the signer returns verified under its PublicKey, and
// refused signature-invalid where it does not verify. A nil signer, or one whose PublicKey is the zero
// PublicKey, is a fault, and panics, as is a body of a type sealdcrypto.JSON does not hold.
func Certify(ctx context.Context, signer Signer, label sealdcrypto.Label, body sealdcrypto.JSON) ([]byte, error) {
	keyOf("certify", signer)
	// A fault is raised whatever the input, so a body with no canonical JSON, a fault under every label,
	// is one before a label that makes no certificate is refused. A body's row is its label's, so only a
	// label that makes a certificate has one to check the body against.
	b, err := canonical.JSON(body)
	if err != nil {
		panic("certify: a body with no canonical JSON, which a reader refuses: " + err.Error())
	}
	if !signature.Certifies(label) {
		return nil, refusal.New(sealdcrypto.RefusalKindUnsupported, "a label that makes no certificate")
	}
	if err := describedByItsRow(label, b); err != nil {
		panic("certify: a body its label's row does not describe, which a reader refuses: " + err.Error())
	}
	message, sig, err := signed(ctx, "certify", signer, label, b)
	if err != nil {
		return nil, err
	}
	return append(message, sig...), nil
}

// describedByItsRow is the refusal a reader gives body, a certificate's canonical JSON under label, as
// it reads it once the certificate verifies, or nil where the reader takes it: the body as Bodies lays
// out label's, and for a card, its recipient id against its key and its window. The checks that need
// what the reader expects, its tenant, person and instant, are not the body's alone, and are not made.
func describedByItsRow(label sealdcrypto.Label, b []byte) error {
	v, err := canonical.ParseJSON(b)
	if err != nil {
		return err
	}
	switch label {
	case sealdcrypto.LabelIdentityAuthority:
		_, err := body.ReadIdentityAuthority(v)
		return err
	case sealdcrypto.LabelCard:
	default:
		panic("certify: a certificate's label with no reader")
	}
	card, err := body.ReadCard(v)
	if err != nil {
		return err
	}
	if !card.NamesItsKey() {
		return refusal.New(sealdcrypto.RefusalKindMalformed, "a card whose recipient id is not that of its public key")
	}
	if !card.HoldsAnInstant() {
		return refusal.New(sealdcrypto.RefusalKindMalformed, "a card whose window holds no instant")
	}
	return nil
}

package verify

import (
	"bytes"
	"slices"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	bodies "github.com/seald-healthcare/crypto-go/internal/body"
	"github.com/seald-healthcare/crypto-go/internal/canonical"
	"github.com/seald-healthcare/crypto-go/internal/public"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
	signatures "github.com/seald-healthcare/crypto-go/internal/signature"
)

// ReadCertificateResult is what ReadCertificate reads: the body, and the bytes it was signed as.
type ReadCertificateResult struct {
	// Body is the body's value, as ParseCanonicalJSON reads it.
	Body sealdcrypto.JSON
	// BodyBytes is the body's canonical JSON, as the issuer signed it.
	BodyBytes []byte
}

// ReadCertificate is the vectors' readCertificate: a certificate, tuple("seald/v1/signature", label,
// body) ‖ signature, verified under issuer and label as received, then its body read. So nothing is
// read from a body before its signature verifies, and a body is only ever read from the very bytes
// signed.
//
// label is sealdcrypto.LabelIdentityAuthority or sealdcrypto.LabelCard; any other, a label v1 has for a
// signature among them, is refused unsupported, before the issuer and any byte of the certificate. It
// refuses invalid-key an issuer whose key cannot sign, an x-wing key, before it reads the certificate,
// so whatever its bytes; malformed bytes that do not parse as a certificate, three parts, then a
// signature of exactly 3373 bytes;
// signature-invalid a certificate whose first part is not "seald/v1/signature", or under another
// label, which no Seald key signed, or whose signature does not verify under issuer, as
// VerifySignature verifies; malformed a body that is not canonical JSON, as ParseCanonicalJSON refuses
// it; and what reading the body refuses, as the Crypto API's Bodies lays out its label's: malformed a
// body that does not hold its label's members alone, each in its one written form, and invalid-key a
// public_key of another algorithm than its label's, or that does not import. A body is the one Bodies
// lays out for its label, or no certificate's.
//
// A result says only that issuer signed the body under label, and that the body is one of its label.
// The caller checks that issuer is the one the flow expects, and what the body names:
// VerifyIdentityAuthority and VerifyCard check both for an identity authority and a card, and
// VerifyCard that a card names its own key and has a window that holds an instant.
//
// The zero PublicKey is a fault, and panics. The result shares nothing with certificate.
func ReadCertificate(certificate []byte, issuer sealdcrypto.PublicKey, label sealdcrypto.Label) (ReadCertificateResult, error) {
	k := checked("readCertificate", issuer)
	return readCertificate("readCertificate", certificate, label, k)
}

// readCertificate is certificate verified under label and any one of issuers, as verifiedBody verifies
// it, and its body read as label's row of Bodies lays it out.
func readCertificate(op string, certificate []byte, label sealdcrypto.Label, issuers ...public.Key) (ReadCertificateResult, error) {
	c, body, err := verifiedBody(certificate, label, issuers...)
	if err != nil {
		return ReadCertificateResult{}, err
	}
	switch label {
	case sealdcrypto.LabelIdentityAuthority:
		_, err = bodies.ReadIdentityAuthority(body)
	case sealdcrypto.LabelCard:
		_, err = bodies.ReadCard(body)
	default:
		panic(op + ": a certificate's label with no reader")
	}
	if err != nil {
		return ReadCertificateResult{}, err
	}
	return ReadCertificateResult{Body: body, BodyBytes: bytes.Clone(c.Body)}, nil
}

// verifiedBody is certificate verified under label and any one of issuers, as ReadCertificate verifies
// it under one, and its body's value as canonical JSON reads it, which the caller reads as its label's.
// Each issuer is checked to sign before the certificate is read, and the certificate is read once,
// then its signature verified under each issuer in turn until one verifies it. issuers is never empty.
func verifiedBody(certificate []byte, label sealdcrypto.Label, issuers ...public.Key) (signatures.Certificate, sealdcrypto.JSON, error) {
	if !signatures.Certifies(label) {
		return signatures.Certificate{}, nil, refusal.New(sealdcrypto.RefusalKindUnsupported, "a label that makes no certificate")
	}
	for _, issuer := range issuers {
		if issuer.Algorithm() == public.XWing {
			return signatures.Certificate{}, nil, refusal.New(sealdcrypto.RefusalKindInvalidKey, "a key that cannot sign")
		}
	}
	c, err := signatures.SplitCertificate(certificate)
	if err != nil {
		return signatures.Certificate{}, nil, err
	}
	if !c.Signed() {
		return signatures.Certificate{}, nil, refusal.New(sealdcrypto.RefusalKindSignatureInvalid, "a certificate whose message is not a signature's")
	}
	if c.Label != label {
		return signatures.Certificate{}, nil, refusal.New(sealdcrypto.RefusalKindSignatureInvalid, "a certificate under another label")
	}
	if !slices.ContainsFunc(issuers, func(issuer public.Key) bool { return signatures.Verify(issuer, c.Message, c.Signature) }) {
		return signatures.Certificate{}, nil, refusal.New(sealdcrypto.RefusalKindSignatureInvalid, "a certificate whose signature does not verify under its issuer")
	}
	body, err := canonical.ParseJSON(c.Body)
	if err != nil {
		return signatures.Certificate{}, nil, err
	}
	return c, body, nil
}

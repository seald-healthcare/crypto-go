package open

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/encoding"
	"github.com/seald-healthcare/crypto-go/internal/public"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
)

// TokenisationKeySize is the size of the tokenisation key Ref takes.
const TokenisationKeySize = 32

// refSize is a ref's size: the first 16 bytes of its HMAC.
const refSize = 16

// RefValue is what Ref is over: a RefValuePerson, a RefValueDevice or a RefValueSubject, each passed
// by value. No other type satisfies it, so each kind's value is laid out as its kind sets and no value
// is taken for another kind's.
type RefValue interface {
	refValue()
}

// RefValuePerson is a ref of kind person, over the person's iss and sub as the identity provider names
// them: the trail's actor ref for a person.
type RefValuePerson struct {
	Person sealdcrypto.Person
}

// RefValueDevice is a ref of kind device, over a device key's recipient id: the trail's actor ref for
// a device.
type RefValueDevice struct {
	RecipientID sealdcrypto.RecipientID
}

// RefValueSubject is a ref of kind subject, over the customer's own identifier for a subject, such as a
// medical record number: the subject ref of a version and its events. Identifier is taken exactly as
// the integration gives it, and nothing normalises it, so " 123" and "123", or "é" composed and
// decomposed, are two subjects: the integration writes one identifier one way.
type RefValueSubject struct {
	Identifier string
}

func (RefValuePerson) refValue()  {}
func (RefValueDevice) refValue()  {}
func (RefValueSubject) refValue() {}

// Ref is the vectors' ref: the first 16 bytes of HMAC-SHA-256(tokenisationKey, tuple("seald/v1/ref",
// kind, …value)), a keyed one-way ref that names value in the trail without disclosing it. Kind person
// is over iss and sub, device over the recipient id, and subject over the identifier's UTF-8.
//
// tokenisationKey is the tenant's tokenisation key of the epoch the ref is made in, a secret of
// TokenisationKeySize bytes that Ref never keeps. The ref hides value only while the key does: whoever
// holds the key tests any guess of a value against a ref, and a subject's identifier is often easy to
// guess. Its size is checked and its entropy cannot be, so a key drawn other than from the CSPRNG lets
// anyone who guesses it test a guess against a ref.
//
// A ref names the same value only under the same key: a ref of another epoch is another ref. It refuses
// malformed where iss, sub or the identifier is not well-formed Unicode. A key of another size, a nil
// value, or a pointer to one of the three, is a fault, and panics.
func Ref(tokenisationKey []byte, value RefValue) ([]byte, error) {
	if len(tokenisationKey) != TokenisationKeySize {
		panic("ref: a tokenisation key that is not 32 bytes")
	}
	var parts [][]byte
	switch v := value.(type) {
	case RefValuePerson:
		iss, ok1 := encoding.Text(v.Person.Iss)
		sub, ok2 := encoding.Text(v.Person.Sub)
		if !ok1 || !ok2 {
			return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "text that is not well-formed Unicode")
		}
		parts = [][]byte{[]byte("person"), iss, sub}
	case RefValueDevice:
		parts = [][]byte{[]byte("device"), encoding.RecipientID(v.RecipientID)}
	case RefValueSubject:
		identifier, ok := encoding.Text(v.Identifier)
		if !ok {
			return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "text that is not well-formed Unicode")
		}
		parts = [][]byte{[]byte("subject"), identifier}
	default:
		panic("ref: no value")
	}
	message := encoding.Tuple(append([][]byte{[]byte("seald/v1/ref")}, parts...)...)
	defer func() {
		clear(message)
		for _, p := range parts {
			clear(p)
		}
	}()
	return mac(tokenisationKey, message)[:refSize:refSize], nil
}

// mac is HMAC-SHA-256(key, message), as ref computes it.
func mac(key, message []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(message)
	return m.Sum(nil)
}

// EnrolmentCodeInput is EnrolmentCode's input, the vectors' enrolmentCode's: what the new device and
// the approver each compute the code from.
type EnrolmentCodeInput struct {
	// RequestID is the request's id, drawn at random by the new device.
	RequestID sealdcrypto.UUID
	Tenant    sealdcrypto.TenantID
	// Person is the person as the new device's sign-in names them.
	Person sealdcrypto.Person
	// PublicKey is the new device's public key.
	PublicKey sealdcrypto.PublicKey
	// Secret is the secret the new device drew, and revealed only once the approver's value existed.
	Secret []byte
	// ApproverValue is the value the approver's client drew when it opened the request.
	ApproverValue []byte
}

// EnrolmentCode is the vectors' enrolmentCode: the first 8 bytes of
// SHA-256(tuple("seald/v1/enrolment-code", request id, tenant id, iss, sub, key export, secret,
// approver's value)) as u64be, modulo 1,000,000, written as six digits with leading zeros. The new
// device and the approver's client each compute it, and a person compares the two.
//
// The code binds the request, the tenant, the person and the key only because the new device committed
// to its secret before the approver's value existed: the approver's client checks the revealed secret
// against the request's secret hash before it computes the code, and EnrolmentCode checks neither. A
// substituted input shows the same code once in a million attempts, so every mismatch is a rejection
// and never a retry. The code is not a secret, and proves nothing on its own.
//
// It takes Secret and ApproverValue at any length, as the tuple carries each behind its own length:
// each is 256 bits, which the caller checks where it reads them from the server. It refuses malformed
// where iss or sub is not well-formed Unicode. The zero PublicKey is a fault, and panics.
func EnrolmentCode(input EnrolmentCodeInput) (string, error) {
	key := public.Key(input.PublicKey)
	if key.IsZero() {
		panic("enrolmentCode: no key")
	}
	iss, ok1 := encoding.Text(input.Person.Iss)
	sub, ok2 := encoding.Text(input.Person.Sub)
	if !ok1 || !ok2 {
		return "", refusal.New(sealdcrypto.RefusalKindMalformed, "text that is not well-formed Unicode")
	}
	message := encoding.Tuple(
		[]byte("seald/v1/enrolment-code"),
		encoding.UUID(input.RequestID),
		encoding.UUID(input.Tenant),
		iss,
		sub,
		key.Export(),
		input.Secret,
		input.ApproverValue,
	)
	defer clear(message)
	sum := sha256.Sum256(message)
	return fmt.Sprintf("%06d", binary.BigEndian.Uint64(sum[:8])%1_000_000), nil
}

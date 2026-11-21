package verify

import (
	"bytes"
	"time"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	bodies "github.com/seald-healthcare/crypto-go/internal/body"
	"github.com/seald-healthcare/crypto-go/internal/public"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
)

// IdentityAuthorityBody is what the anchor signs in an identity authority's certificate, under the
// identity-authority label.
type IdentityAuthorityBody struct {
	// TenantID is the tenant whose cards the identity authority signs.
	TenantID sealdcrypto.TenantID
	// PublicKey is the identity authority's key, an ed25519+ml-dsa-65 key.
	PublicKey sealdcrypto.PublicKey
	// IssuedAt is when the anchor certified it, in UTC and whole seconds.
	IssuedAt time.Time
}

// CardBody is what the identity authority signs in a card, under the card label.
type CardBody struct {
	// RecipientID is the recipient id of PublicKey.
	RecipientID sealdcrypto.RecipientID
	// TenantID is the tenant the card is in.
	TenantID sealdcrypto.TenantID
	// Person is the person hash, 32 bytes, never the subject itself.
	Person []byte
	// PublicKey is the device key the card certifies, an x-wing+ed25519+ml-dsa-65 key.
	PublicKey sealdcrypto.PublicKey
	// IssuedAt and ValidUntil are the card's window, in UTC and whole seconds: it holds at IssuedAt and
	// after, and before ValidUntil.
	IssuedAt   time.Time
	ValidUntil time.Time
	// Replaces is the recipient id of the card this one replaces, and nil where it replaces none.
	Replaces *sealdcrypto.RecipientID
}

// VerifyCardInput is VerifyCard's input.
type VerifyCardInput struct {
	// Card is the card's certificate, as received.
	Card []byte
	// IdentityAuthority is the certificate of the tenant's identity authority, as received.
	IdentityAuthority []byte
	// Anchor is the anchor compiled into the release, never one fetched.
	Anchor sealdcrypto.PublicKey
	// Tenant is the tenant expected.
	Tenant sealdcrypto.TenantID
	// Person is the person expected.
	Person sealdcrypto.Person
	// At is the instant asked about.
	At time.Time
}

// VerifyIdentityAuthority is the vectors' verifyIdentityAuthority, step 1 of VerifyCard: the
// identity authority's certificate verified under anchor as ReadCertificate verifies it, then checked to
// name tenant, tenant-mismatch otherwise. Anchors are per environment, so only the tenant it names ties
// the certificate to a tenant.
//
// anchor is the one compiled into the release, never a key fetched. The zero PublicKey is a fault, and
// panics.
func VerifyIdentityAuthority(certificate []byte, anchor sealdcrypto.PublicKey, tenant sealdcrypto.TenantID) (IdentityAuthorityBody, error) {
	checked("verifyIdentityAuthority", anchor)
	return verifyIdentityAuthority(certificate, anchor, tenant)
}

func verifyIdentityAuthority(certificate []byte, anchor sealdcrypto.PublicKey, tenant sealdcrypto.TenantID) (IdentityAuthorityBody, error) {
	_, v, err := verifiedBody(certificate, sealdcrypto.LabelIdentityAuthority, public.Key(anchor))
	if err != nil {
		return IdentityAuthorityBody{}, err
	}
	read, err := bodies.ReadIdentityAuthority(v)
	if err != nil {
		return IdentityAuthorityBody{}, err
	}
	body := IdentityAuthorityBody(read)
	if body.TenantID != tenant {
		return IdentityAuthorityBody{}, refusal.New(sealdcrypto.RefusalKindTenantMismatch, "an identity authority's certificate that names another tenant")
	}
	return body, nil
}

// VerifyCard is the vectors' verifyCard: a card checked offline for what its device does now, in the
// Crypto API's order, each check refused with its kind:
//
//  1. IdentityAuthority verifies under Anchor and names Tenant, as VerifyIdentityAuthority checks it.
//  2. Card verifies under that identity authority, under the card label, and names Tenant.
//  3. Its recipient id is its key's, and its window holds an instant.
//  4. Its person hash is Person's in Tenant.
//  5. At is inside its window.
//
// Person is read before any byte, so one not well-formed Unicode is refused malformed first. Anchor is
// the one compiled into the release, never one fetched, and Tenant and Person the ones the caller
// expects, or the check proves nothing. A card revoked or replaced passes: whether it is active is the
// word of the server that stores cards. A signature kept and verified long after it was made is
// checked with VerifyKeptCard instead.
//
// The zero Anchor is a fault, and panics.
func VerifyCard(input VerifyCardInput) (CardBody, error) {
	checked("verifyCard", input.Anchor)
	person, err := PersonHash(input.Tenant, input.Person)
	if err != nil {
		return CardBody{}, err
	}
	authority, err := verifyIdentityAuthority(input.IdentityAuthority, input.Anchor, input.Tenant)
	if err != nil {
		return CardBody{}, err
	}
	return verifyCard(input.Card, []public.Key{public.Key(authority.PublicKey)}, input.Tenant, person, input.At)
}

// VerifyCardUnderIdentityAuthorityInput is VerifyCardUnderIdentityAuthority's input.
type VerifyCardUnderIdentityAuthorityInput struct {
	// Card is the card's certificate, as received.
	Card []byte
	// IdentityAuthorityKeys are Tenant's identity authorities' public keys, one, or two while the anchor
	// rotates, held from a source the caller trusts for Tenant, never from the card's sender. A key
	// given twice counts once. An empty list, one of more than MaxIdentityAuthorities keys, and a zero
	// PublicKey in it are faults.
	IdentityAuthorityKeys []sealdcrypto.PublicKey
	// Tenant is the tenant expected.
	Tenant sealdcrypto.TenantID
	// Person is the person expected.
	Person sealdcrypto.Person
	// At is the instant asked about.
	At time.Time
}

// VerifyCardUnderIdentityAuthority is the vectors' verifyCardUnderIdentityAuthority: VerifyCard's
// steps 2 to 5, under any one of IdentityAuthorityKeys, for a component that holds no anchor. Person is
// read first, then each key is checked to be ed25519+ml-dsa-65, invalid-key otherwise, before any byte
// of the card.
//
// Nothing here ties the keys to Tenant, since no anchor's certificate is checked: a card that passes
// proves no more than the source the caller took the keys from.
func VerifyCardUnderIdentityAuthority(input VerifyCardUnderIdentityAuthorityInput) (CardBody, error) {
	authorities := identityAuthorities("verifyCardUnderIdentityAuthority", input.IdentityAuthorityKeys)
	person, err := PersonHash(input.Tenant, input.Person)
	if err != nil {
		return CardBody{}, err
	}
	if err := eachAnIdentityAuthority(authorities); err != nil {
		return CardBody{}, err
	}
	return verifyCard(input.Card, authorities, input.Tenant, person, input.At)
}

// VerifyKeptCardInput is VerifyKeptCard's input. It asks for no person and no instant.
type VerifyKeptCardInput struct {
	// Card is the signer's card's certificate, as received.
	Card []byte
	// IdentityAuthority is the certificate of the tenant's identity authority, as received.
	IdentityAuthority []byte
	// Anchor is the anchor compiled into the release, never one fetched.
	Anchor sealdcrypto.PublicKey
	// Tenant is the tenant expected.
	Tenant sealdcrypto.TenantID
}

// VerifyKeptCard is the vectors' verifyKeptCard: the card of a kept signature's signer, one kept and
// verified long after it was made, such as an epoch body's or an envelope's, checked in VerifyCard's
// steps 1 to 3 alone. So a card whose window has ended, or that was replaced or revoked since, still
// passes, and what it signed stays verifiable.
//
// It checks nothing of who the signer is or when it signed: never use it to admit a device, or for a
// signature made now, which VerifyCard checks.
//
// The zero Anchor is a fault, and panics.
func VerifyKeptCard(input VerifyKeptCardInput) (CardBody, error) {
	checked("verifyKeptCard", input.Anchor)
	authority, err := verifyIdentityAuthority(input.IdentityAuthority, input.Anchor, input.Tenant)
	if err != nil {
		return CardBody{}, err
	}
	read, err := keptCard(input.Card, []public.Key{public.Key(authority.PublicKey)}, input.Tenant)
	return CardBody(read), err
}

// VerifyKeptCardUnderIdentityAuthorityInput is VerifyKeptCardUnderIdentityAuthority's input.
type VerifyKeptCardUnderIdentityAuthorityInput struct {
	// Card is the signer's card's certificate, as received.
	Card []byte
	// IdentityAuthorityKeys are as VerifyCardUnderIdentityAuthorityInput's.
	IdentityAuthorityKeys []sealdcrypto.PublicKey
	// Tenant is the tenant expected.
	Tenant sealdcrypto.TenantID
}

// VerifyKeptCardUnderIdentityAuthority is the vectors' verifyKeptCardUnderIdentityAuthority:
// VerifyKeptCard from its step 2, under any one of IdentityAuthorityKeys, each checked as
// VerifyCardUnderIdentityAuthority checks it before any byte of the card.
func VerifyKeptCardUnderIdentityAuthority(input VerifyKeptCardUnderIdentityAuthorityInput) (CardBody, error) {
	authorities := identityAuthorities("verifyKeptCardUnderIdentityAuthority", input.IdentityAuthorityKeys)
	if err := eachAnIdentityAuthority(authorities); err != nil {
		return CardBody{}, err
	}
	read, err := keptCard(input.Card, authorities, input.Tenant)
	return CardBody(read), err
}

// keptCard is steps 2 and 3 of the card check, in order. It returns the zero card with a refusal.
func keptCard(certificate []byte, authorities []public.Key, tenant sealdcrypto.TenantID) (bodies.Card, error) {
	_, v, err := verifiedBody(certificate, sealdcrypto.LabelCard, authorities...)
	if err != nil {
		return bodies.Card{}, err
	}
	read, err := bodies.ReadCard(v)
	if err != nil {
		return bodies.Card{}, err
	}
	if read.TenantID != tenant {
		return bodies.Card{}, refusal.New(sealdcrypto.RefusalKindTenantMismatch, "a card that names another tenant")
	}
	if !read.NamesItsKey() {
		return bodies.Card{}, refusal.New(sealdcrypto.RefusalKindMalformed, "a card whose recipient id is not that of its public key")
	}
	if !read.HoldsAnInstant() {
		return bodies.Card{}, refusal.New(sealdcrypto.RefusalKindMalformed, "a card whose window holds no instant")
	}
	return read, nil
}

// verifyCard is steps 2 to 5 of the card check, in order, person being the hash of the person expected,
// which the caller read before any byte.
func verifyCard(certificate []byte, authorities []public.Key, tenant sealdcrypto.TenantID, person []byte, at time.Time) (CardBody, error) {
	read, err := keptCard(certificate, authorities, tenant)
	if err != nil {
		return CardBody{}, err
	}
	card := CardBody(read)
	if !bytes.Equal(person, card.Person) {
		return CardBody{}, refusal.New(sealdcrypto.RefusalKindPersonMismatch, "a card whose person hash is not that of the person expected")
	}
	if at.Before(card.IssuedAt) || !at.Before(card.ValidUntil) {
		return CardBody{}, refusal.New(sealdcrypto.RefusalKindOutsideWindow, "a card asked about at an instant outside its window")
	}
	return card, nil
}

package body

import (
	"slices"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
)

// The purposes of each label whose body holds one.
const (
	PurposeOpen            = "open"
	PurposeResume          = "resume"
	PurposeRevokeDevice    = "revoke-device"
	PurposeRequestRotation = "request-rotation"
	PurposeRemovePasskey   = "remove-passkey"
	PurposeOffboard        = "offboard"
	PurposeSuspend         = "suspend"
	PurposeReinstate       = "reinstate"
	PurposeGive            = "give"
	PurposeRemove          = "remove"
	PurposeSetOwnerMinimum = "set-owner-minimum"
	PurposeRegister        = "register"
	PurposeSeal            = "seal"
	PurposeAsk             = "ask"
	PurposeCommit          = "commit"
)

var purposes = map[sealdcrypto.Label][]string{
	sealdcrypto.LabelSession:     {PurposeOpen, PurposeResume},
	sealdcrypto.LabelRevocation:  {PurposeRevokeDevice, PurposeRequestRotation, PurposeRemovePasskey, PurposeOffboard},
	sealdcrypto.LabelPersonState: {PurposeSuspend, PurposeReinstate},
	sealdcrypto.LabelRole:        {PurposeGive, PurposeRemove, PurposeSetOwnerMinimum},
	sealdcrypto.LabelPasskey:     {PurposeRegister, PurposeSeal},
	sealdcrypto.LabelRecovery:    {PurposeAsk, PurposeCommit},
}

// purposeOf reads v's purpose before any other member, so a body signed for one purpose never passes
// for another. A purpose its label does not name is malformed, never unsupported, whatever v1 has
// elsewhere.
func purposeOf(label sealdcrypto.Label, v sealdcrypto.JSON) (string, error) {
	s, err := purposeText(v)
	if err != nil {
		return "", err
	}
	if !slices.Contains(purposes[label], s) {
		return "", refusal.New(sealdcrypto.RefusalKindMalformed, "a body's purpose its label does not name")
	}
	return s, nil
}

// purposeText reads v's purpose as text, whichever purpose it names.
func purposeText(v sealdcrypto.JSON) (string, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return "", refusal.New(sealdcrypto.RefusalKindMalformed, "a body, or an object in it, that is not an object")
	}
	p, ok := m["purpose"]
	if !ok {
		return "", refusal.New(sealdcrypto.RefusalKindMalformed, "a body, or an object in it, with a member missing")
	}
	s, ok := p.(string)
	if !ok {
		return "", refusal.New(sealdcrypto.RefusalKindMalformed, "a body's member that is not text")
	}
	return s, nil
}

// Revocation is a body under revocation. A member its purpose does not name is the zero value.
type Revocation struct {
	Purpose     string
	TenantID    sealdcrypto.TenantID
	RecipientID *sealdcrypto.RecipientID
	Reason      string
	EveryDevice bool
	PasskeyID   *sealdcrypto.UUID
	Person      []byte
}

// A revocation's reasons.
const (
	ReasonLost    = "lost"
	ReasonStolen  = "stolen"
	ReasonRetired = "retired"
)

// ReadRevocation reads a body under revocation.
func ReadRevocation(v sealdcrypto.JSON) (Revocation, error) {
	purpose, err := purposeOf(sealdcrypto.LabelRevocation, v)
	if err != nil {
		return Revocation{}, err
	}
	required := map[string][]string{
		PurposeRevokeDevice:    {"purpose", "tenant_id", "recipient_id", "reason"},
		PurposeRequestRotation: {"purpose", "tenant_id"},
		PurposeRemovePasskey:   {"purpose", "tenant_id", "passkey_id"},
		PurposeOffboard:        {"purpose", "tenant_id", "person"},
	}[purpose]
	var optional []string
	if purpose == PurposeRequestRotation {
		optional = []string{"recipient_id", "every_device"}
	}
	m, err := members(v, required, optional...)
	if err != nil {
		return Revocation{}, err
	}
	r := Revocation{Purpose: purpose}
	if r.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return Revocation{}, err
	}
	switch purpose {
	case PurposeRevokeDevice:
		id, err := recipientIDOf(m, "recipient_id")
		if err != nil {
			return Revocation{}, err
		}
		r.RecipientID = &id
		if r.Reason, err = reasonOf(m, "reason"); err != nil {
			return Revocation{}, err
		}
	case PurposeRequestRotation:
		_, one := m["recipient_id"]
		_, every := m["every_device"]
		switch {
		case one && every:
			return Revocation{}, refusal.New(sealdcrypto.RefusalKindMalformed, "a rotation request naming a device and every device")
		case one:
			id, err := recipientIDOf(m, "recipient_id")
			if err != nil {
				return Revocation{}, err
			}
			r.RecipientID = &id
		case every:
			if m["every_device"] != true {
				return Revocation{}, refusal.New(sealdcrypto.RefusalKindMalformed, "an every_device that is not true")
			}
			r.EveryDevice = true
		default:
			return Revocation{}, refusal.New(sealdcrypto.RefusalKindMalformed, "a body, or an object in it, with a member missing")
		}
	case PurposeRemovePasskey:
		id, err := uuidOf(m, "passkey_id")
		if err != nil {
			return Revocation{}, err
		}
		r.PasskeyID = &id
	case PurposeOffboard:
		if r.Person, err = bytesOf(m, "person", HashSize); err != nil {
			return Revocation{}, err
		}
	}
	return r, nil
}

func reasonOf(m map[string]any, name string) (string, error) {
	s, err := textOf(m, name)
	if err != nil {
		return "", err
	}
	if s != ReasonLost && s != ReasonStolen && s != ReasonRetired {
		return "", refusal.New(sealdcrypto.RefusalKindMalformed, "a revocation's reason that is not lost, stolen or retired")
	}
	return s, nil
}

type PersonState struct {
	Purpose  string
	TenantID sealdcrypto.TenantID
	Person   []byte
}

func ReadPersonState(v sealdcrypto.JSON) (PersonState, error) {
	purpose, err := purposeOf(sealdcrypto.LabelPersonState, v)
	if err != nil {
		return PersonState{}, err
	}
	m, err := members(v, []string{"purpose", "tenant_id", "person"})
	if err != nil {
		return PersonState{}, err
	}
	p := PersonState{Purpose: purpose}
	if p.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return PersonState{}, err
	}
	if p.Person, err = bytesOf(m, "person", HashSize); err != nil {
		return PersonState{}, err
	}
	return p, nil
}

// Role is a body under role. A member its purpose does not name is the zero value.
type Role struct {
	Purpose      string
	TenantID     sealdcrypto.TenantID
	Person       []byte
	Role         string
	OwnerMinimum uint64
}

// ReadRole reads a body under role. A role is read for its form alone: which roles a tenant has is not
// a body's.
func ReadRole(v sealdcrypto.JSON) (Role, error) {
	purpose, err := purposeOf(sealdcrypto.LabelRole, v)
	if err != nil {
		return Role{}, err
	}
	required := []string{"purpose", "tenant_id", "person", "role"}
	if purpose == PurposeSetOwnerMinimum {
		required = []string{"purpose", "tenant_id", "owner_minimum"}
	}
	m, err := members(v, required)
	if err != nil {
		return Role{}, err
	}
	r := Role{Purpose: purpose}
	if r.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return Role{}, err
	}
	if purpose == PurposeSetOwnerMinimum {
		if r.OwnerMinimum, err = countOf(m, "owner_minimum"); err != nil {
			return Role{}, err
		}
		return r, nil
	}
	if r.Person, err = bytesOf(m, "person", HashSize); err != nil {
		return Role{}, err
	}
	if r.Role, err = textOf(m, "role"); err != nil {
		return Role{}, err
	}
	if r.Role == "" {
		return Role{}, refusal.New(sealdcrypto.RefusalKindMalformed, "a body naming an empty role")
	}
	return r, nil
}

// Passkey is a body under passkey. PasskeyKey is nil for seal.
type Passkey struct {
	Purpose      string
	TenantID     sealdcrypto.TenantID
	Person       []byte
	CredentialID []byte
	PasskeyKey   []byte
}

func ReadPasskey(v sealdcrypto.JSON) (Passkey, error) {
	purpose, err := purposeOf(sealdcrypto.LabelPasskey, v)
	if err != nil {
		return Passkey{}, err
	}
	required := []string{"purpose", "tenant_id", "person", "credential_id"}
	if purpose == PurposeRegister {
		required = append(required, "passkey_key")
	}
	m, err := members(v, required)
	if err != nil {
		return Passkey{}, err
	}
	p := Passkey{Purpose: purpose}
	if p.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return Passkey{}, err
	}
	if p.Person, err = bytesOf(m, "person", HashSize); err != nil {
		return Passkey{}, err
	}
	if p.CredentialID, err = passkeyBytesOf(m, "credential_id"); err != nil {
		return Passkey{}, err
	}
	if purpose == PurposeRegister {
		if p.PasskeyKey, err = passkeyBytesOf(m, "passkey_key"); err != nil {
			return Passkey{}, err
		}
	}
	return p, nil
}

// passkeyBytesOf reads non-empty bytes, and nothing more: passkey_key is never parsed as COSE, since
// that it is what WebAuthn registered is the relying party's to check.
func passkeyBytesOf(m map[string]any, name string) ([]byte, error) {
	b, err := bytesOf(m, name, -1)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "a passkey's credential id or key that is empty")
	}
	return b, nil
}

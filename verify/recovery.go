package verify

import (
	sealdcrypto "github.com/seald-healthcare/crypto-go"
	bodies "github.com/seald-healthcare/crypto-go/internal/body"
	"github.com/seald-healthcare/crypto-go/internal/canonical"
)

// RecoveryPurpose is what a body under recovery is signed for, and names its other members.
type RecoveryPurpose string

// The purposes of a body under recovery.
const (
	RecoveryPurposeAsk    RecoveryPurpose = bodies.PurposeAsk
	RecoveryPurposeCommit RecoveryPurpose = bodies.PurposeCommit
)

// RecoveryBody is a key recovery's ask or commit. A member its Purpose does not name is the zero value,
// so switch on Purpose first.
type RecoveryBody struct {
	Purpose  RecoveryPurpose
	TenantID sealdcrypto.TenantID
	// Domains is in the body's order, and nil where AllDomains is true.
	Domains    []sealdcrypto.Locator
	AllDomains bool
	// Person is the new owner's person hash.
	Person []byte
	// ReasonCode is read for its form alone: check it against the codes you know.
	ReasonCode string
	// Reference is text the Owner typed, such as a ticket, possibly empty: escape it as untrusted text.
	Reference string
	// RecoveryID is the recovery a commit is for, as the service drew it when it recorded the recovery.
	RecoveryID sealdcrypto.UUID
	// SlicesHash is read for its form alone: compare it with the JSON hash of the domains the request
	// carries.
	SlicesHash []byte
}

// ReadRecoveryBody reads a key recovery's ask or commit from its bytes as signed under
// sealdcrypto.LabelRecovery.
//
// An ask holds nothing fresh, so the same ask signed twice gives the same bytes: accept it only in a
// request made under a fresh unlock. Verify a commit's signature over the body rebuilt from the
// recovery the request names, so a commit made for another recovery does not verify.
func ReadRecoveryBody(body []byte) (RecoveryBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return RecoveryBody{}, err
	}
	b, err := bodies.ReadRecovery(v)
	if err != nil {
		return RecoveryBody{}, err
	}
	return RecoveryBody{
		Purpose: RecoveryPurpose(b.Purpose), TenantID: b.TenantID, Domains: b.Domains, AllDomains: b.AllDomains, Person: b.Person,
		ReasonCode: b.ReasonCode, Reference: b.Reference, RecoveryID: b.RecoveryID, SlicesHash: b.SlicesHash,
	}, nil
}

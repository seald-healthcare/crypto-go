// Package body reads each signed JSON body, for verify's readers and for sign before it certifies.
//
// Each reader checks every member's form in its row's order, then what members hold together, then
// each key, so a body that fails several checks gets the first refusal. Refusal details are constants
// that quote nothing of the body.
package body

import (
	"crypto/mldsa"
	"encoding/base64"
	"slices"
	"strings"
	"time"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/canonical"
	"github.com/seald-healthcare/crypto-go/internal/keyimport"
	"github.com/seald-healthcare/crypto-go/internal/public"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
)

const HashSize = 32

type IdentityAuthority struct {
	TenantID  sealdcrypto.TenantID
	PublicKey sealdcrypto.PublicKey
	IssuedAt  time.Time
}

// Session is a session's opening or resume. AgentAttestation is nil where there is none.
type Session struct {
	Purpose          string
	TenantID         sealdcrypto.TenantID
	Nonce            []byte
	SessionKey       SessionKey
	AgentAttestation *AgentAttestation
}

// AgentAttestation is an AI agent's measurements, and Runtime nil where its runtime vouches for none.
type AgentAttestation struct {
	Measurements Measurements
	Runtime      []byte
}

type Measurements struct {
	Code          []byte
	SDKRelease    string
	ModelProvider string
	Model         string
	Configuration []byte
}

type SessionKey struct {
	Algorithm string
	Value     []byte
}

const (
	// SessionKeyP256's value is the uncompressed point (SEC 1, 2.3.3).
	SessionKeyP256        = "p-256"
	SessionKeyP256Size    = 65
	SessionKeyMLDSA65     = "ml-dsa-65"
	SessionKeyMLDSA65Size = mldsa.MLDSA65PublicKeySize
	uncompressed          = 0x04
	NonceSize             = 32
)

type Card struct {
	RecipientID sealdcrypto.RecipientID
	TenantID    sealdcrypto.TenantID
	Person      []byte
	PublicKey   sealdcrypto.PublicKey
	IssuedAt    time.Time
	ValidUntil  time.Time
	Replaces    *sealdcrypto.RecipientID
}

// NamesItsKey is whether the card's recipient id is its public key's.
func (c Card) NamesItsKey() bool {
	return public.Key(c.PublicKey).RecipientID() == c.RecipientID
}

// HoldsAnInstant is whether valid_until is after issued_at.
func (c Card) HoldsAnInstant() bool {
	return c.ValidUntil.After(c.IssuedAt)
}

type Request struct {
	RequestID  sealdcrypto.UUID
	TenantID   sealdcrypto.TenantID
	Person     []byte
	PublicKey  sealdcrypto.PublicKey
	SecretHash []byte
	Replaces   *sealdcrypto.RecipientID
}

// Rotation is a rotation request, read alike under rotation and under enrolment.
type Rotation struct {
	RotationID sealdcrypto.UUID
	TenantID   sealdcrypto.TenantID
	Person     []byte
	PublicKey  sealdcrypto.PublicKey
	Replaces   sealdcrypto.RecipientID
}

type Approval struct {
	RequestID sealdcrypto.UUID
	TenantID  sealdcrypto.TenantID
	Person    []byte
	PublicKey sealdcrypto.PublicKey
	Code      string
	Replaces  *sealdcrypto.RecipientID
}

// Invitation is an invitation. VendorID and SetupCodeHash are nil where it names none.
type Invitation struct {
	InvitationID  sealdcrypto.UUID
	TenantID      sealdcrypto.TenantID
	EmailHash     []byte
	Roles         []string
	VendorID      *sealdcrypto.UUID
	SetupCodeHash []byte
	ExpiresAt     time.Time
}

type Registration struct {
	TenantID    sealdcrypto.TenantID
	PublicKey   sealdcrypto.PublicKey
	Fingerprint []byte
}

// The algorithm of each key a body names.
const (
	identityAuthority = sealdcrypto.AlgorithmEd25519MLDSA65
	deviceKey         = sealdcrypto.AlgorithmXWingEd25519MLDSA65
	backupKey         = sealdcrypto.AlgorithmXWing
)

// Read is the vectors' readBody: b read as the label's body, under enrolment an enrolment request and
// under backfill an escrow commit, and returned as its JSON value. A label with no body is a fault.
func Read(label sealdcrypto.Label, b []byte) (sealdcrypto.JSON, error) {
	read, ok := readers[label]
	if !ok {
		panic("readBody: a label whose body Bodies does not lay out")
	}
	v, err := canonical.ParseJSON(b)
	if err != nil {
		return nil, err
	}
	if err := read(v); err != nil {
		return nil, err
	}
	return v, nil
}

var readers = map[sealdcrypto.Label]func(sealdcrypto.JSON) error{
	sealdcrypto.LabelIdentityAuthority: func(v sealdcrypto.JSON) error { _, err := ReadIdentityAuthority(v); return err },
	sealdcrypto.LabelSession:           func(v sealdcrypto.JSON) error { _, err := ReadSession(v); return err },
	sealdcrypto.LabelCard:              func(v sealdcrypto.JSON) error { _, err := ReadCard(v); return err },
	sealdcrypto.LabelEnrolment:         func(v sealdcrypto.JSON) error { _, err := ReadRequest(v); return err },
	sealdcrypto.LabelRotation:          func(v sealdcrypto.JSON) error { _, err := ReadRotation(v); return err },
	sealdcrypto.LabelApproval:          func(v sealdcrypto.JSON) error { _, err := ReadApproval(v); return err },
	sealdcrypto.LabelInvitation:        func(v sealdcrypto.JSON) error { _, err := ReadInvitation(v); return err },
	sealdcrypto.LabelRegistration:      func(v sealdcrypto.JSON) error { _, err := ReadRegistration(v); return err },
	sealdcrypto.LabelDeviceCall:        func(v sealdcrypto.JSON) error { _, err := ReadDeviceCall(v); return err },
	sealdcrypto.LabelUnlock:            func(v sealdcrypto.JSON) error { _, err := ReadUnlock(v); return err },
	sealdcrypto.LabelEpoch:             func(v sealdcrypto.JSON) error { _, err := ReadEpoch(v); return err },
	sealdcrypto.LabelShare:             func(v sealdcrypto.JSON) error { _, err := ReadEscrowCommit(v); return err },
	sealdcrypto.LabelBackfill:          func(v sealdcrypto.JSON) error { _, err := ReadEscrowCommit(v); return err },
	sealdcrypto.LabelJoin:              func(v sealdcrypto.JSON) error { _, err := ReadEscrowCommit(v); return err },
	sealdcrypto.LabelDelegation:        func(v sealdcrypto.JSON) error { _, err := ReadEscrowCommit(v); return err },
	sealdcrypto.LabelOwnership:         func(v sealdcrypto.JSON) error { _, err := ReadOwnership(v); return err },
	sealdcrypto.LabelMove:              func(v sealdcrypto.JSON) error { _, err := ReadMove(v); return err },
	sealdcrypto.LabelCommit:            func(v sealdcrypto.JSON) error { _, err := ReadCommit(v); return err },
	sealdcrypto.LabelRevocation:        func(v sealdcrypto.JSON) error { _, err := ReadRevocation(v); return err },
	sealdcrypto.LabelPersonState:       func(v sealdcrypto.JSON) error { _, err := ReadPersonState(v); return err },
	sealdcrypto.LabelPasskey:           func(v sealdcrypto.JSON) error { _, err := ReadPasskey(v); return err },
	sealdcrypto.LabelRole:              func(v sealdcrypto.JSON) error { _, err := ReadRole(v); return err },
	sealdcrypto.LabelAccount:           func(v sealdcrypto.JSON) error { _, err := ReadAccount(v); return err },
	sealdcrypto.LabelAgentState:        func(v sealdcrypto.JSON) error { _, err := ReadAgentState(v); return err },
	sealdcrypto.LabelManifest:          func(v sealdcrypto.JSON) error { _, err := ReadSessionManifest(v); return err },
	sealdcrypto.LabelRecovery:          func(v sealdcrypto.JSON) error { _, err := ReadRecovery(v); return err },
}

func ReadIdentityAuthority(v sealdcrypto.JSON) (IdentityAuthority, error) {
	m, err := members(v, []string{"tenant_id", "public_key", "issued_at"})
	if err != nil {
		return IdentityAuthority{}, err
	}
	var b IdentityAuthority
	var key keyText
	if b.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return IdentityAuthority{}, err
	}
	if key, err = keyOf(m["public_key"]); err != nil {
		return IdentityAuthority{}, err
	}
	if b.IssuedAt, err = instantOf(m, "issued_at"); err != nil {
		return IdentityAuthority{}, err
	}
	if b.PublicKey, err = key.imported(identityAuthority); err != nil {
		return IdentityAuthority{}, err
	}
	return b, nil
}

// ReadSession reads a session's opening or resume. A p-256 session key is checked for its form alone,
// not for being on the curve.
func ReadSession(v sealdcrypto.JSON) (Session, error) {
	purpose, err := purposeOf(sealdcrypto.LabelSession, v)
	if err != nil {
		return Session{}, err
	}
	return readSession(v, purpose)
}

// ReadSessionOpening reads a session body as an opening alone: any other purpose, one v1 has under
// session among them, is refused malformed before any other member is read.
func ReadSessionOpening(v sealdcrypto.JSON) (Session, error) {
	purpose, err := purposeText(v)
	if err != nil {
		return Session{}, err
	}
	if purpose != PurposeOpen {
		return Session{}, refusal.New(sealdcrypto.RefusalKindMalformed, "a session body read as an opening whose purpose is not open")
	}
	return readSession(v, purpose)
}

// readSession reads every member but purpose, already read.
func readSession(v sealdcrypto.JSON, purpose string) (Session, error) {
	m, err := members(v, []string{"purpose", "tenant_id", "nonce", "session_key"}, "agent_attestation")
	if err != nil {
		return Session{}, err
	}
	s := Session{Purpose: purpose}
	var key keyText
	if s.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return Session{}, err
	}
	if s.Nonce, err = bytesOf(m, "nonce", NonceSize); err != nil {
		return Session{}, err
	}
	if key, err = keyOf(m["session_key"]); err != nil {
		return Session{}, err
	}
	if err := sessionKeyForm(key); err != nil {
		return Session{}, err
	}
	s.SessionKey = SessionKey{Algorithm: key.algorithm, Value: key.value}
	if a, ok := m["agent_attestation"]; ok {
		attestation, err := agentAttestationOf(a)
		if err != nil {
			return Session{}, err
		}
		s.AgentAttestation = &attestation
	}
	if s.AgentAttestation != nil && s.Purpose != PurposeOpen {
		return Session{}, refusal.New(sealdcrypto.RefusalKindMalformed, "a session's resume holding an AI agent's attestation")
	}
	return s, nil
}

func agentAttestationOf(v any) (AgentAttestation, error) {
	a, err := members(v, []string{"measurements"}, "runtime")
	if err != nil {
		return AgentAttestation{}, err
	}
	m, err := members(a["measurements"], []string{"code", "sdk_release", "model_provider", "model", "configuration"})
	if err != nil {
		return AgentAttestation{}, err
	}
	var at AgentAttestation
	if at.Measurements.Code, err = bytesOf(m, "code", HashSize); err != nil {
		return AgentAttestation{}, err
	}
	if at.Measurements.SDKRelease, err = textOf(m, "sdk_release"); err != nil {
		return AgentAttestation{}, err
	}
	if at.Measurements.ModelProvider, err = textOf(m, "model_provider"); err != nil {
		return AgentAttestation{}, err
	}
	if at.Measurements.Model, err = textOf(m, "model"); err != nil {
		return AgentAttestation{}, err
	}
	if at.Measurements.Configuration, err = bytesOf(m, "configuration", HashSize); err != nil {
		return AgentAttestation{}, err
	}
	if _, ok := a["runtime"]; ok {
		if at.Runtime, err = base64Of(a["runtime"]); err != nil {
			return AgentAttestation{}, err
		}
	}
	return at, nil
}

// base64Of reads padded standard base64 strictly, one text per bytes. The empty text gives empty bytes,
// never nil, so a member present is never taken for one absent.
func base64Of(v any) ([]byte, error) {
	s, ok := v.(string)
	if !ok {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "a body's member that is not text")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "a body's member that is not its bytes in base64")
	}
	if b == nil {
		b = []byte{}
	}
	return b, nil
}

// sessionKeyForm checks a session key's algorithm and value for their form alone, since no session key
// is imported.
func sessionKeyForm(k keyText) error {
	switch k.algorithm {
	case SessionKeyP256:
		if len(k.value) != SessionKeyP256Size || k.value[0] != uncompressed {
			return refusal.New(sealdcrypto.RefusalKindMalformed, "a p-256 session key that is not an uncompressed point")
		}
	case SessionKeyMLDSA65:
		if len(k.value) != SessionKeyMLDSA65Size {
			return refusal.New(sealdcrypto.RefusalKindMalformed, "an ml-dsa-65 session key that is not 1952 bytes")
		}
	default:
		return refusal.New(sealdcrypto.RefusalKindMalformed, "a session key of an algorithm a session key does not have")
	}
	return nil
}

// ReadCard reads a card's body. NamesItsKey and HoldsAnInstant give the card's own checks.
func ReadCard(v sealdcrypto.JSON) (Card, error) {
	m, err := members(v, []string{"recipient_id", "tenant_id", "person", "public_key", "issued_at", "valid_until"}, "replaces")
	if err != nil {
		return Card{}, err
	}
	var c Card
	var key keyText
	if c.RecipientID, err = recipientIDOf(m, "recipient_id"); err != nil {
		return Card{}, err
	}
	if c.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return Card{}, err
	}
	if c.Person, err = bytesOf(m, "person", HashSize); err != nil {
		return Card{}, err
	}
	if key, err = keyOf(m["public_key"]); err != nil {
		return Card{}, err
	}
	if c.IssuedAt, err = instantOf(m, "issued_at"); err != nil {
		return Card{}, err
	}
	if c.ValidUntil, err = instantOf(m, "valid_until"); err != nil {
		return Card{}, err
	}
	if c.Replaces, err = optionalRecipientID(m, "replaces"); err != nil {
		return Card{}, err
	}
	if c.PublicKey, err = key.imported(deviceKey); err != nil {
		return Card{}, err
	}
	return c, nil
}

func ReadRequest(v sealdcrypto.JSON) (Request, error) {
	m, err := members(v, []string{"request_id", "tenant_id", "person", "public_key", "secret_hash"}, "replaces")
	if err != nil {
		return Request{}, err
	}
	var r Request
	var key keyText
	if r.RequestID, err = uuidOf(m, "request_id"); err != nil {
		return Request{}, err
	}
	if r.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return Request{}, err
	}
	if r.Person, err = bytesOf(m, "person", HashSize); err != nil {
		return Request{}, err
	}
	if key, err = keyOf(m["public_key"]); err != nil {
		return Request{}, err
	}
	if r.SecretHash, err = bytesOf(m, "secret_hash", HashSize); err != nil {
		return Request{}, err
	}
	if r.Replaces, err = optionalRecipientID(m, "replaces"); err != nil {
		return Request{}, err
	}
	if r.PublicKey, err = key.imported(deviceKey); err != nil {
		return Request{}, err
	}
	return r, nil
}

func ReadRotation(v sealdcrypto.JSON) (Rotation, error) {
	m, err := members(v, []string{"rotation_id", "tenant_id", "person", "public_key", "replaces"})
	if err != nil {
		return Rotation{}, err
	}
	var r Rotation
	var key keyText
	if r.RotationID, err = uuidOf(m, "rotation_id"); err != nil {
		return Rotation{}, err
	}
	if r.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return Rotation{}, err
	}
	if r.Person, err = bytesOf(m, "person", HashSize); err != nil {
		return Rotation{}, err
	}
	if key, err = keyOf(m["public_key"]); err != nil {
		return Rotation{}, err
	}
	if r.Replaces, err = recipientIDOf(m, "replaces"); err != nil {
		return Rotation{}, err
	}
	if r.PublicKey, err = key.imported(deviceKey); err != nil {
		return Rotation{}, err
	}
	return r, nil
}

func ReadApproval(v sealdcrypto.JSON) (Approval, error) {
	m, err := members(v, []string{"request_id", "tenant_id", "person", "public_key", "code"}, "replaces")
	if err != nil {
		return Approval{}, err
	}
	var a Approval
	var key keyText
	if a.RequestID, err = uuidOf(m, "request_id"); err != nil {
		return Approval{}, err
	}
	if a.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return Approval{}, err
	}
	if a.Person, err = bytesOf(m, "person", HashSize); err != nil {
		return Approval{}, err
	}
	if key, err = keyOf(m["public_key"]); err != nil {
		return Approval{}, err
	}
	if a.Code, err = codeOf(m, "code"); err != nil {
		return Approval{}, err
	}
	if a.Replaces, err = optionalRecipientID(m, "replaces"); err != nil {
		return Approval{}, err
	}
	if a.PublicKey, err = key.imported(deviceKey); err != nil {
		return Approval{}, err
	}
	return a, nil
}

// ReadInvitation reads an invitation. Its roles are checked for their form alone: which roles a tenant
// has is not a body's.
func ReadInvitation(v sealdcrypto.JSON) (Invitation, error) {
	m, err := members(v, []string{"invitation_id", "tenant_id", "email_hash", "roles", "expires_at"}, "vendor_id", "setup_code_hash")
	if err != nil {
		return Invitation{}, err
	}
	var i Invitation
	if i.InvitationID, err = uuidOf(m, "invitation_id"); err != nil {
		return Invitation{}, err
	}
	if i.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return Invitation{}, err
	}
	if i.EmailHash, err = bytesOf(m, "email_hash", HashSize); err != nil {
		return Invitation{}, err
	}
	if i.Roles, err = rolesOf(m, "roles"); err != nil {
		return Invitation{}, err
	}
	if _, ok := m["vendor_id"]; ok {
		id, err := uuidOf(m, "vendor_id")
		if err != nil {
			return Invitation{}, err
		}
		i.VendorID = &id
	}
	if _, ok := m["setup_code_hash"]; ok {
		if i.SetupCodeHash, err = bytesOf(m, "setup_code_hash", HashSize); err != nil {
			return Invitation{}, err
		}
	}
	if i.ExpiresAt, err = instantOf(m, "expires_at"); err != nil {
		return Invitation{}, err
	}
	return i, nil
}

// ReadRegistration reads a backup key's registration. Its fingerprint is checked against public_key as
// written, before the key is imported.
func ReadRegistration(v sealdcrypto.JSON) (Registration, error) {
	m, err := members(v, []string{"tenant_id", "public_key", "fingerprint"})
	if err != nil {
		return Registration{}, err
	}
	var r Registration
	var key keyText
	if r.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return Registration{}, err
	}
	if key, err = keyOf(m["public_key"]); err != nil {
		return Registration{}, err
	}
	if r.Fingerprint, err = bytesOf(m, "fingerprint", HashSize); err != nil {
		return Registration{}, err
	}
	// A key of another algorithm has a digest too, and is refused for its algorithm only after.
	if digest := public.New(key.algorithm, key.value).Digest(); !slices.Equal(digest[:], r.Fingerprint) {
		return Registration{}, refusal.New(sealdcrypto.RefusalKindMalformed, "a registration whose fingerprint is not its key's digest")
	}

	if r.PublicKey, err = key.imported(backupKey); err != nil {
		return Registration{}, err
	}
	return r, nil
}

type DeviceCall struct {
	TenantID sealdcrypto.TenantID
	Method   string
	Path     string
	BodyHash []byte
	At       time.Time
}

type Unlock struct {
	TenantID  sealdcrypto.TenantID
	UnlockID  sealdcrypto.UUID
	Nonce     []byte
	Requests  []UnlockRequest
	ExpiresAt time.Time
}

type UnlockRequest struct {
	RequestID sealdcrypto.UUID
	Method    string
	Path      string
	BodyHash  []byte
}

type Epoch struct {
	TenantID          sealdcrypto.TenantID
	Root              sealdcrypto.Locator
	Epoch             uint64
	KeyDigest         []byte
	EventID           sealdcrypto.UUID
	BackupFingerprint []byte
	SlicesHash        []byte
}

// EscrowCommit is a commit on a key domain's escrow, one body under share, backfill, join and
// delegation.
type EscrowCommit struct {
	TenantID      sealdcrypto.TenantID
	Root          sealdcrypto.Locator
	EscrowVersion uint64
	EventID       sealdcrypto.UUID
	SlicesHash    []byte
}

// RecordRecipientCommit is a record recipient's commit, the body under share and backfill that is not
// an escrow commit.
type RecordRecipientCommit struct {
	TenantID   sealdcrypto.TenantID
	Locator    sealdcrypto.Locator
	Person     []byte
	EventID    sealdcrypto.UUID
	SlicesHash []byte
}

// TokenisationKeyBackfill is the tokenisation key's backfill, the third body under backfill.
type TokenisationKeyBackfill struct {
	TenantID    sealdcrypto.TenantID
	RecipientID sealdcrypto.RecipientID
	EventID     sealdcrypto.UUID
	WrapsHash   []byte
}

type Ownership struct {
	TenantID sealdcrypto.TenantID
	Root     sealdcrypto.Locator
	Person   []byte
}

// Move is a move's commit. Root is the key domain the object moves to, and Epoch the target's epoch
// the keys are wrapped to.
type Move struct {
	TenantID   sealdcrypto.TenantID
	Locator    sealdcrypto.Locator
	Root       sealdcrypto.Locator
	EventID    sealdcrypto.UUID
	Epoch      uint64
	SlicesHash []byte
}

// MaxCommitEvents is the most events one commit completes.
const MaxCommitEvents = 100

type Commit struct {
	TenantID   sealdcrypto.TenantID
	Root       sealdcrypto.Locator
	LeaseID    sealdcrypto.UUID
	EventIDs   []sealdcrypto.UUID
	Epoch      uint64
	CommitHash []byte
}

func ReadDeviceCall(v sealdcrypto.JSON) (DeviceCall, error) {
	m, err := members(v, []string{"tenant_id", "method", "path", "body_hash", "at"})
	if err != nil {
		return DeviceCall{}, err
	}
	var d DeviceCall
	if d.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return DeviceCall{}, err
	}
	if d.Method, err = methodOf(m, "method"); err != nil {
		return DeviceCall{}, err
	}
	if d.Path, err = pathOf(m, "path"); err != nil {
		return DeviceCall{}, err
	}
	if d.BodyHash, err = bytesOf(m, "body_hash", HashSize); err != nil {
		return DeviceCall{}, err
	}
	if d.At, err = instantOf(m, "at"); err != nil {
		return DeviceCall{}, err
	}
	return d, nil
}

// ReadUnlock reads a fresh unlock. A request_id given twice is requests' own form, so it is refused
// before expires_at is read.
func ReadUnlock(v sealdcrypto.JSON) (Unlock, error) {
	m, err := members(v, []string{"tenant_id", "unlock_id", "nonce", "requests", "expires_at"})
	if err != nil {
		return Unlock{}, err
	}
	var u Unlock
	if u.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return Unlock{}, err
	}
	if u.UnlockID, err = uuidOf(m, "unlock_id"); err != nil {
		return Unlock{}, err
	}
	if u.Nonce, err = bytesOf(m, "nonce", NonceSize); err != nil {
		return Unlock{}, err
	}
	if u.Requests, err = requestsOf(m, "requests"); err != nil {
		return Unlock{}, err
	}
	if u.ExpiresAt, err = instantOf(m, "expires_at"); err != nil {
		return Unlock{}, err
	}
	return u, nil
}

func requestsOf(m map[string]any, name string) ([]UnlockRequest, error) {
	list, ok := m[name].([]any)
	if !ok {
		return nil, notOfItsForm
	}
	if len(list) == 0 {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "an unlock approving no request")
	}
	requests := make([]UnlockRequest, 0, len(list))
	// seen keeps the check linear in the requests, however many a body names.
	seen := make(map[sealdcrypto.UUID]bool, len(list))
	for _, v := range list {
		r, err := members(v, []string{"request_id", "method", "path", "body_hash"})
		if err != nil {
			return nil, err
		}
		var q UnlockRequest
		if q.RequestID, err = uuidOf(r, "request_id"); err != nil {
			return nil, err
		}
		if q.Method, err = methodOf(r, "method"); err != nil {
			return nil, err
		}
		if q.Path, err = pathOf(r, "path"); err != nil {
			return nil, err
		}
		if q.BodyHash, err = bytesOf(r, "body_hash", HashSize); err != nil {
			return nil, err
		}
		if seen[q.RequestID] {
			return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "an unlock naming a request twice")
		}
		seen[q.RequestID] = true
		requests = append(requests, q)
	}
	return requests, nil
}

// ReadEpoch reads a key domain's new epoch. key_digest is read for its form alone, and checked by each
// unwrap of the epoch's key.
func ReadEpoch(v sealdcrypto.JSON) (Epoch, error) {
	m, err := members(v, []string{"tenant_id", "root", "epoch", "key_digest", "event_id", "backup_fingerprint", "slices_hash"})
	if err != nil {
		return Epoch{}, err
	}
	var e Epoch
	if e.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return Epoch{}, err
	}
	if e.Root, err = locatorOf(m, "root"); err != nil {
		return Epoch{}, err
	}
	if e.Epoch, err = countOf(m, "epoch"); err != nil {
		return Epoch{}, err
	}
	if e.KeyDigest, err = bytesOf(m, "key_digest", HashSize); err != nil {
		return Epoch{}, err
	}
	if e.EventID, err = uuidOf(m, "event_id"); err != nil {
		return Epoch{}, err
	}
	if e.BackupFingerprint, err = bytesOf(m, "backup_fingerprint", HashSize); err != nil {
		return Epoch{}, err
	}
	if e.SlicesHash, err = bytesOf(m, "slices_hash", HashSize); err != nil {
		return Epoch{}, err
	}
	return e, nil
}

func ReadEscrowCommit(v sealdcrypto.JSON) (EscrowCommit, error) {
	m, err := members(v, []string{"tenant_id", "root", "escrow_version", "event_id", "slices_hash"})
	if err != nil {
		return EscrowCommit{}, err
	}
	var e EscrowCommit
	if e.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return EscrowCommit{}, err
	}
	if e.Root, err = locatorOf(m, "root"); err != nil {
		return EscrowCommit{}, err
	}
	if e.EscrowVersion, err = countOf(m, "escrow_version"); err != nil {
		return EscrowCommit{}, err
	}
	if e.EventID, err = uuidOf(m, "event_id"); err != nil {
		return EscrowCommit{}, err
	}
	if e.SlicesHash, err = bytesOf(m, "slices_hash", HashSize); err != nil {
		return EscrowCommit{}, err
	}
	return e, nil
}

func ReadRecordRecipientCommit(v sealdcrypto.JSON) (RecordRecipientCommit, error) {
	m, err := members(v, []string{"tenant_id", "locator", "person", "event_id", "slices_hash"})
	if err != nil {
		return RecordRecipientCommit{}, err
	}
	var r RecordRecipientCommit
	if r.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return RecordRecipientCommit{}, err
	}
	if r.Locator, err = locatorOf(m, "locator"); err != nil {
		return RecordRecipientCommit{}, err
	}
	if r.Person, err = bytesOf(m, "person", HashSize); err != nil {
		return RecordRecipientCommit{}, err
	}
	if r.EventID, err = uuidOf(m, "event_id"); err != nil {
		return RecordRecipientCommit{}, err
	}
	if r.SlicesHash, err = bytesOf(m, "slices_hash", HashSize); err != nil {
		return RecordRecipientCommit{}, err
	}
	return r, nil
}

func ReadTokenisationKeyBackfill(v sealdcrypto.JSON) (TokenisationKeyBackfill, error) {
	m, err := members(v, []string{"tenant_id", "recipient_id", "event_id", "wraps_hash"})
	if err != nil {
		return TokenisationKeyBackfill{}, err
	}
	var b TokenisationKeyBackfill
	if b.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return TokenisationKeyBackfill{}, err
	}
	if b.RecipientID, err = recipientIDOf(m, "recipient_id"); err != nil {
		return TokenisationKeyBackfill{}, err
	}
	if b.EventID, err = uuidOf(m, "event_id"); err != nil {
		return TokenisationKeyBackfill{}, err
	}
	if b.WrapsHash, err = bytesOf(m, "wraps_hash", HashSize); err != nil {
		return TokenisationKeyBackfill{}, err
	}
	return b, nil
}

func ReadOwnership(v sealdcrypto.JSON) (Ownership, error) {
	m, err := members(v, []string{"tenant_id", "root", "person"})
	if err != nil {
		return Ownership{}, err
	}
	var o Ownership
	if o.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return Ownership{}, err
	}
	if o.Root, err = locatorOf(m, "root"); err != nil {
		return Ownership{}, err
	}
	if o.Person, err = bytesOf(m, "person", HashSize); err != nil {
		return Ownership{}, err
	}
	return o, nil
}

func ReadMove(v sealdcrypto.JSON) (Move, error) {
	m, err := members(v, []string{"tenant_id", "locator", "root", "event_id", "epoch", "slices_hash"})
	if err != nil {
		return Move{}, err
	}
	var b Move
	if b.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return Move{}, err
	}
	if b.Locator, err = locatorOf(m, "locator"); err != nil {
		return Move{}, err
	}
	if b.Root, err = locatorOf(m, "root"); err != nil {
		return Move{}, err
	}
	if b.EventID, err = uuidOf(m, "event_id"); err != nil {
		return Move{}, err
	}
	if b.Epoch, err = countOf(m, "epoch"); err != nil {
		return Move{}, err
	}
	if b.SlicesHash, err = bytesOf(m, "slices_hash", HashSize); err != nil {
		return Move{}, err
	}
	return b, nil
}

func ReadCommit(v sealdcrypto.JSON) (Commit, error) {
	m, err := members(v, []string{"tenant_id", "root", "lease_id", "event_ids", "epoch", "commit_hash"})
	if err != nil {
		return Commit{}, err
	}
	var c Commit
	if c.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return Commit{}, err
	}
	if c.Root, err = locatorOf(m, "root"); err != nil {
		return Commit{}, err
	}
	if c.LeaseID, err = uuidOf(m, "lease_id"); err != nil {
		return Commit{}, err
	}
	if c.EventIDs, err = eventIDsOf(m, "event_ids"); err != nil {
		return Commit{}, err
	}
	if c.Epoch, err = countOf(m, "epoch"); err != nil {
		return Commit{}, err
	}
	if c.CommitHash, err = bytesOf(m, "commit_hash", HashSize); err != nil {
		return Commit{}, err
	}
	return c, nil
}

// eventIDsOf reads a commit's events, in the lease's order, which it keeps.
func eventIDsOf(m map[string]any, name string) ([]sealdcrypto.UUID, error) {
	list, ok := m[name].([]any)
	if !ok {
		return nil, notOfItsForm
	}
	if len(list) == 0 || len(list) > MaxCommitEvents {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "a commit of no event or of more than 100")
	}
	ids := make([]sealdcrypto.UUID, 0, len(list))
	seen := make(map[sealdcrypto.UUID]bool, len(list))
	for _, v := range list {
		s, ok := v.(string)
		if !ok {
			return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "a body's member that is not text")
		}
		id, err := sealdcrypto.ParseUUID(s)
		if err != nil {
			return nil, err
		}
		if seen[id] {
			return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "a commit naming an event twice")
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids, nil
}

// methodOf reads RFC 9110's token (5.6.2) with no lower-case letter, so a method has one text.
func methodOf(m map[string]any, name string) (string, error) {
	s, err := textOf(m, name)
	if err != nil {
		return "", err
	}
	if s == "" || slices.ContainsFunc([]byte(s), func(c byte) bool { return !upperTchar(c) }) {
		return "", refusal.New(sealdcrypto.RefusalKindMalformed, "a method that is not a token in upper case")
	}
	return s, nil
}

func upperTchar(c byte) bool {
	switch {
	case 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	default:
		return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
	}
}

// pathOf checks a path for its leading / alone, since the verifier rebuilds it from the call and
// compares it byte for byte.
func pathOf(m map[string]any, name string) (string, error) {
	s, err := textOf(m, name)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(s, "/") {
		return "", refusal.New(sealdcrypto.RefusalKindMalformed, "a path that does not begin with /")
	}
	return s, nil
}

func locatorOf(m map[string]any, name string) (sealdcrypto.Locator, error) {
	s, err := textOf(m, name)
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", refusal.New(sealdcrypto.RefusalKindMalformed, "an empty locator")
	}
	return sealdcrypto.Locator(s), nil
}

func countOf(m map[string]any, name string) (uint64, error) {
	n, ok := m[name].(int64)
	if !ok || n < 1 {
		return 0, refusal.New(sealdcrypto.RefusalKindMalformed, "a body's member that is not an integer from 1")
	}
	return uint64(n), nil //nolint:gosec // n is from 1, checked above
}

var notOfItsForm = refusal.New(sealdcrypto.RefusalKindMalformed, "a body's member that is not of its form")

// members is v's members, refused unless v is an object holding each of required, and no member but
// required and optional.
func members(v sealdcrypto.JSON, required []string, optional ...string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "a body, or an object in it, that is not an object")
	}
	for _, name := range required {
		if _, ok := m[name]; !ok {
			return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "a body, or an object in it, with a member missing")
		}
	}
	for name := range m {
		if !slices.Contains(required, name) && !slices.Contains(optional, name) {
			return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "a body, or an object in it, with a member it does not have")
		}
	}
	return m, nil
}

func textOf(m map[string]any, name string) (string, error) {
	s, ok := m[name].(string)
	if !ok {
		return "", refusal.New(sealdcrypto.RefusalKindMalformed, "a body's member that is not text")
	}
	return s, nil
}

func rolesOf(m map[string]any, name string) ([]string, error) {
	list, ok := m[name].([]any)
	if !ok {
		return nil, notOfItsForm
	}
	roles := make([]string, 0, len(list))
	// seen keeps the check linear in the roles, however many a body names.
	seen := make(map[string]bool, len(list))
	for _, v := range list {
		s, ok := v.(string)
		if !ok {
			return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "a body's member that is not text")
		}
		if s == "" {
			return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "an invitation naming an empty role")
		}
		if seen[s] {
			return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "an invitation naming a role twice")
		}
		seen[s] = true
		roles = append(roles, s)
	}
	return roles, nil
}

func uuidOf(m map[string]any, name string) (sealdcrypto.UUID, error) {
	s, err := textOf(m, name)
	if err != nil {
		return sealdcrypto.UUID{}, err
	}
	return sealdcrypto.ParseUUID(s)
}

// bytesOf reads bytes in JSON of size bytes, or any length where size is -1.
func bytesOf(m map[string]any, name string, size int) ([]byte, error) {
	return bytesOfValue(m[name], size)
}

// bytesOfValue reads unpadded base64url strictly, so bytes have one text.
func bytesOfValue(v any, size int) ([]byte, error) {
	s, ok := v.(string)
	if !ok {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "a body's member that is not text")
	}
	if size >= 0 && len(s) != base64.RawURLEncoding.EncodedLen(size) {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "a body's member that is not its bytes in JSON")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "a body's member that is not its bytes in JSON")
	}
	return b, nil
}

func recipientIDOf(m map[string]any, name string) (sealdcrypto.RecipientID, error) {
	return recipientIDOfValue(m[name])
}

func recipientIDOfValue(v any) (sealdcrypto.RecipientID, error) {
	b, err := bytesOfValue(v, len(sealdcrypto.RecipientID{}))
	if err != nil {
		return sealdcrypto.RecipientID{}, err
	}
	return sealdcrypto.RecipientID(b), nil
}

func optionalRecipientID(m map[string]any, name string) (*sealdcrypto.RecipientID, error) {
	if _, ok := m[name]; !ok {
		return nil, nil
	}
	id, err := recipientIDOf(m, name)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func codeOf(m map[string]any, name string) (string, error) {
	s, err := textOf(m, name)
	if err != nil {
		return "", err
	}
	if len(s) != 6 || slices.ContainsFunc([]byte(s), func(c byte) bool { return c < '0' || c > '9' }) {
		return "", refusal.New(sealdcrypto.RefusalKindMalformed, "an enrolment code that is not six digits")
	}
	return s, nil
}

// Instant is an instant's one text in a body.
const Instant = "2006-01-02T15:04:05Z"

// instantOf writes the instant read again and compares, so one instant has one text. time.Parse takes
// no second of 60, which is refused.
func instantOf(m map[string]any, name string) (time.Time, error) {
	s, err := textOf(m, name)
	if err != nil {
		return time.Time{}, err
	}
	t, err := time.Parse(Instant, s)
	if err != nil || t.Format(Instant) != s {
		return time.Time{}, refusal.New(sealdcrypto.RefusalKindMalformed, "a body's instant that is not YYYY-MM-DDTHH:MM:SSZ")
	}
	return t, nil
}

type keyText struct {
	algorithm string
	value     []byte
}

func keyOf(v any) (keyText, error) {
	k, err := members(v, []string{"algorithm", "value"})
	if err != nil {
		return keyText{}, err
	}
	algorithm, err := textOf(k, "algorithm")
	if err != nil {
		return keyText{}, err
	}
	value, err := bytesOf(k, "value", -1)
	if err != nil {
		return keyText{}, err
	}
	return keyText{algorithm: algorithm, value: value}, nil
}

// imported refuses a key of another algorithm before its value is imported.
func (k keyText) imported(algorithm sealdcrypto.Algorithm) (sealdcrypto.PublicKey, error) {
	if sealdcrypto.Algorithm(k.algorithm) != algorithm {
		return sealdcrypto.PublicKey{}, refusal.New(sealdcrypto.RefusalKindInvalidKey, "a body's key of another algorithm")
	}
	return keyimport.Public(algorithm, k.value)
}

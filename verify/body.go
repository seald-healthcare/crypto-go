package verify

import (
	"time"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	bodies "github.com/seald-healthcare/crypto-go/internal/body"
	"github.com/seald-healthcare/crypto-go/internal/canonical"
)

// Each reader below is one body of the Crypto API's Bodies, read from its bytes as signed: canonical
// JSON, holding exactly the members its row names, each in its one written form. A reader is told which
// body it reads, as a verifier is told the label it verifies, so one label may have more than one body:
// the caller picks the reader for the body it expects, never one by what the bytes hold.
//
// Each checks a body in Bodies' one order, so a body that fails two checks gets one refusal: every
// member's form, in the order its row names them; then what its members hold together; then each key,
// its algorithm first and then as ImportPublicKey imports it. It refuses malformed bytes that are not
// canonical JSON, as ParseCanonicalJSON refuses them, a member missing, one its row does not name, and
// one in another form, and invalid-key a key of another algorithm than its member names, one v1 does
// not have among them, or one that does not import. A refusal's detail quotes nothing of the body.
//
// Reading a body checks its bytes and nothing of who signed them. The caller verifies their signature
// first, under the label and the signer its flow expects, with VerifySignature, and reads those very
// bytes, never a copy re-encoded: a body read from bytes nobody signed proves nothing. What a body
// names, such as its tenant, is the caller's to check against what it expects.

// SessionBody is a session's opening or resume, what the device key signs under session.
type SessionBody struct {
	// Purpose is SessionPurposeOpen at a session's opening and SessionPurposeResume at its resume.
	Purpose SessionPurpose
	// TenantID is the tenant the session is in.
	TenantID sealdcrypto.TenantID
	// Nonce is the nonce as the server issued it, its 32 bytes. That it is the single-use nonce the
	// server issued to this device and tenant, unspent, is the server's to compare, in constant time
	// where it treats the nonce as a secret.
	Nonce []byte
	// SessionKey is the session's key: at an opening the key the session is bound to, and at a resume
	// the session's own key, which the caller compares with the one it holds for the session.
	SessionKey SessionKey
	// AgentAttestation is an AI agent's attestation, at an opening alone, and nil where the body holds
	// none. Whether an agent must present one, and with a runtime's attestation, is the caller's to
	// check against the agent's registration: a body without one reads, whoever signed it.
	AgentAttestation *AgentAttestation
}

// AgentAttestation is what an AI agent presents at a session's opening, covered by the device key's
// signature.
type AgentAttestation struct {
	// Measurements are the agent's, which the caller compares with those its registration names.
	Measurements AgentMeasurements
	// Runtime is the runtime's own attestation of the measurements and the session key, its bytes as
	// signed, and nil where the body holds none. The body writes it in base64, the standard alphabet
	// with its padding exactly as RFC 4648, section 4, writes it, and any other text, unpadded or in
	// the URL alphabet among them, is refused malformed. It is read for its form alone: verifying it,
	// against the root the registration names, is the caller's.
	Runtime []byte
}

// AgentMeasurements are an AI agent's measurements, as a session body's agent_attestation carries
// them: what code, SDK release, model and configuration the agent runs.
type AgentMeasurements struct {
	// Code is the SHA-256 of the agent's code, a container image's or a package's digest, 32 bytes.
	Code []byte
	// SDKRelease, ModelProvider and Model are as the text signed, checked as text alone.
	SDKRelease    string
	ModelProvider string
	Model         string
	// Configuration is the SHA-256 of the agent's configuration, 32 bytes.
	Configuration []byte
}

// SessionPurpose is what a session body is signed for: a session's opening or its resume.
type SessionPurpose string

// The purposes of a session body.
const (
	SessionPurposeOpen   SessionPurpose = bodies.PurposeOpen
	SessionPurposeResume SessionPurpose = bodies.PurposeResume
)

// SessionKeyAlgorithm is a session key's algorithm. A session key is generated and held by the
// platform's key store, outside this library, and is no PublicKey: neither algorithm is one of the
// Algorithm constants, and no proof under a session key is this library's to verify.
type SessionKeyAlgorithm string

// The algorithms a session key has.
const (
	// SessionKeyAlgorithmP256 is ECDSA's P-256. Its value is the uncompressed point, 65 bytes, 0x04 ‖ X ‖
	// Y (SEC 1, 2.3.3).
	SessionKeyAlgorithmP256 SessionKeyAlgorithm = bodies.SessionKeyP256
	// SessionKeyAlgorithmMLDSA65 is ML-DSA-65. Its value is the public key's 1952 bytes (FIPS 204).
	SessionKeyAlgorithmMLDSA65 SessionKeyAlgorithm = bodies.SessionKeyMLDSA65
)

// SessionKey is a session key as a session body writes it.
type SessionKey struct {
	Algorithm SessionKeyAlgorithm
	// Value is the key, in its algorithm's form, checked for that form alone: its length, and for a
	// P-256 key its leading 0x04. A P-256 point is not checked to be on the curve, so a caller parses it
	// with a parser that checks it, such as crypto/ecdsa's ParseUncompressedPublicKey, before it verifies
	// a proof under it, and refuses the key where the parser does.
	Value []byte
}

// EnrolmentRequestBody is an enrolment request, what a new device key signs under enrolment.
type EnrolmentRequestBody struct {
	// RequestID is the request's id, drawn at random by the new device.
	RequestID sealdcrypto.UUID
	// TenantID is the tenant the device enrols in.
	TenantID sealdcrypto.TenantID
	// Person is the person hash, 32 bytes.
	Person []byte
	// PublicKey is the new device key, an x-wing+ed25519+ml-dsa-65 key.
	PublicKey sealdcrypto.PublicKey
	// SecretHash is the secret hash of the enrolment secret, 32 bytes.
	SecretHash []byte
	// Replaces is the recipient id of the card the device replaces, and nil where it replaces none.
	Replaces *sealdcrypto.RecipientID
}

// RotationRequestBody is a rotation request, what the key being replaced signs under rotation, vouching
// for its successor, and the new key signs under enrolment.
type RotationRequestBody struct {
	// RotationID is the rotation's id, drawn at random by the rotating client.
	RotationID sealdcrypto.UUID
	// TenantID is the tenant the device is in.
	TenantID sealdcrypto.TenantID
	// Person is the person hash, 32 bytes.
	Person []byte
	// PublicKey is the new device key, an x-wing+ed25519+ml-dsa-65 key.
	PublicKey sealdcrypto.PublicKey
	// Replaces is the recipient id of the card the rotation replaces, which a rotation always names.
	Replaces sealdcrypto.RecipientID
}

// ApprovalBody is an approval of an enrolment request, what the approver's device key signs under
// approval.
type ApprovalBody struct {
	// RequestID, TenantID, Person and PublicKey are the request's, as the approver approves it.
	RequestID sealdcrypto.UUID
	TenantID  sealdcrypto.TenantID
	Person    []byte
	PublicKey sealdcrypto.PublicKey
	// Code is the enrolment code the approver compared, six digits as text.
	Code string
	// Replaces is the recipient id of the card the request replaces, and nil where it names none.
	Replaces *sealdcrypto.RecipientID
}

// InvitationBody is an invitation, what the inviter's device key signs under invitation.
type InvitationBody struct {
	InvitationID sealdcrypto.UUID
	TenantID     sealdcrypto.TenantID
	// EmailHash is the invitee's email hash, 32 bytes.
	EmailHash []byte
	// Roles are role names as text, none empty and none twice, and empty where the invitation names
	// none. Which roles a tenant has, and which an inviter may grant, are the caller's to check.
	Roles []string
	// VendorID is the vendor the invitation names, and nil where it names none.
	VendorID *sealdcrypto.UUID
	// SetupCodeHash is the secret hash of the setup code, 32 bytes, and nil where there is none.
	SetupCodeHash []byte
	// ExpiresAt is when the invitation expires, in UTC and whole seconds.
	ExpiresAt time.Time
}

// RegistrationBody is a backup key's registration, what the minting Owner's device key signs under
// registration, and the identity authority under backup-key.
type RegistrationBody struct {
	TenantID sealdcrypto.TenantID
	// PublicKey is the backup key, an x-wing key, and Fingerprint its key digest, which the reader
	// checks.
	PublicKey   sealdcrypto.PublicKey
	Fingerprint []byte
}

// ReadSessionBody reads a session's opening or resume, what the device key signs under session:
// purpose, open or resume, as text; tenant_id; nonce, its 32 bytes as bytes in JSON; session_key, its
// algorithm p-256, its value the uncompressed point, 65 bytes beginning 0x04, or ml-dsa-65, its value
// 1952 bytes; and agent_attestation, an AI agent's, at an opening alone: measurements, of code and
// configuration, each 32 bytes as bytes in JSON, and sdk_release, model_provider and model, as text,
// and runtime, bytes in JSON in base64, where the agent's runtime vouches for them. Every other bytes
// member is base64url without padding, and runtime is base64, the standard alphabet with its padding:
// each is read strictly, so bytes have one text.
//
// Every check refuses malformed: a member missing, one more, or one in another form, in an attestation
// and its measurements as in the body, a runtime that is not its bytes' one base64 text, unpadded or in
// the URL alphabet among them; a purpose other than open and resume; a session key of another
// algorithm, of a value of another length, or a p-256 value that is not an uncompressed point; and,
// once every member's form is read, an attestation at a resume. A p-256 point is not checked to be on
// the curve.
//
// It reads the body and nothing of who signed it. A caller verifies the signature over these very bytes
// first, with VerifySignature under sealdcrypto.LabelSession and the device key of a card it checked,
// then compares what the body names with what it expects: its tenant, the nonce it issued, unspent, and
// at a resume the session's own key.
func ReadSessionBody(body []byte) (SessionBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return SessionBody{}, err
	}
	b, err := bodies.ReadSession(v)
	if err != nil {
		return SessionBody{}, err
	}
	return SessionBody{
		Purpose:          SessionPurpose(b.Purpose),
		TenantID:         b.TenantID,
		Nonce:            b.Nonce,
		SessionKey:       SessionKey{Algorithm: SessionKeyAlgorithm(b.SessionKey.Algorithm), Value: b.SessionKey.Value},
		AgentAttestation: attestation(b.AgentAttestation),
	}, nil
}

// attestation is a's members as AgentAttestation holds them, and nil where a is.
func attestation(a *bodies.AgentAttestation) *AgentAttestation {
	if a == nil {
		return nil
	}
	return &AgentAttestation{Measurements: AgentMeasurements(a.Measurements), Runtime: a.Runtime}
}

// ReadIdentityAuthorityBody reads the body of an identity authority's certificate: tenant_id,
// public_key, an ed25519+ml-dsa-65 key, and issued_at, as ReadCertificate and VerifyIdentityAuthority
// read a certificate's body once its signature verifies.
//
// It refuses malformed bytes that are not canonical JSON, and a member missing, one its row does not
// name, or one in another form, then invalid-key a public_key of another algorithm, one v1 does not
// have among them, or one that does not import, in Bodies' one order: every member's form first, then
// the key.
//
// It reads the body and nothing of who signed it. The caller verifies the certificate's signature over
// these very bytes first, under the anchor, as VerifyIdentityAuthority does, then checks what the body
// names, such as its tenant.
func ReadIdentityAuthorityBody(body []byte) (IdentityAuthorityBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return IdentityAuthorityBody{}, err
	}
	b, err := bodies.ReadIdentityAuthority(v)
	if err != nil {
		return IdentityAuthorityBody{}, err
	}
	return IdentityAuthorityBody(b), nil
}

// ReadCardBody reads the body of a card, its form alone: that its recipient id is its key's and its
// window holds an instant are checked by VerifyCard and VerifyKeptCard.
//
// It reads nothing of who signed it, so a caller that reads a card here first verifies its signature
// over these very bytes under the identity authority.
func ReadCardBody(body []byte) (CardBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return CardBody{}, err
	}
	b, err := bodies.ReadCard(v)
	if err != nil {
		return CardBody{}, err
	}
	return CardBody(b), nil
}

// ReadEnrolmentRequestBody reads an enrolment request: request_id, tenant_id, person, public_key, an
// x-wing+ed25519+ml-dsa-65 key, secret_hash, and replaces where the device replaces a card. What a
// rotation's new key signs under the same label is a rotation request, which ReadRotationRequestBody
// reads, and this reader refuses.
//
// It refuses malformed bytes that are not canonical JSON, and a member missing, one its row does not
// name, or one in another form, then invalid-key a public_key of another algorithm, one v1 does not
// have among them, or one that does not import, in Bodies' one order: every member's form first, then
// the key.
//
// It reads the body and nothing of who signed it. The caller verifies the signature over these very
// bytes first, with VerifySignature under sealdcrypto.LabelEnrolment and PublicKey, then checks what
// the body names. Where a web client's device key is sealed under a passkey, the registration or
// assertion sent beside the request is over the passkey challenge PasskeyChallengeEnrolment gives over
// these bytes.
func ReadEnrolmentRequestBody(body []byte) (EnrolmentRequestBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return EnrolmentRequestBody{}, err
	}
	b, err := bodies.ReadRequest(v)
	if err != nil {
		return EnrolmentRequestBody{}, err
	}
	return EnrolmentRequestBody(b), nil
}

// ReadRotationRequestBody reads a rotation request: rotation_id, tenant_id, person, public_key, the new
// x-wing+ed25519+ml-dsa-65 key, and replaces, the card it replaces. It is one body under two labels, so a
// caller reads both signatures' bytes with it: the key being replaced signs it under rotation, and the
// new key under enrolment. It refuses malformed a member missing, one more, or one in another form, an
// enrolment request's secret_hash or request_id among them, and invalid-key a key of another algorithm
// or one that does not import, checked after every member's form.
//
// It reads the body and nothing of who signed it. A caller verifies both signatures over these very
// bytes first, with VerifySignature, under sealdcrypto.LabelRotation and the key of the card Replaces
// names, and under sealdcrypto.LabelEnrolment and PublicKey, then checks what the body names: that
// Replaces is the card it expects to rotate, in TenantID, naming Person. A signature under one label
// proves nothing under the other.
func ReadRotationRequestBody(body []byte) (RotationRequestBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return RotationRequestBody{}, err
	}
	b, err := bodies.ReadRotation(v)
	if err != nil {
		return RotationRequestBody{}, err
	}
	return RotationRequestBody(b), nil
}

// ReadApprovalBody reads an approval of an enrolment request: request_id, tenant_id, person,
// public_key, the new device's x-wing+ed25519+ml-dsa-65 key, code, and replaces where the request names
// one.
//
// It refuses malformed bytes that are not canonical JSON, and a member missing, one its row does not
// name, or one in another form, then invalid-key a public_key of another algorithm, one v1 does not
// have among them, or one that does not import, in Bodies' one order: every member's form first, then
// the key.
//
// It reads the body and nothing of who signed it. The caller verifies the signature over these very
// bytes first, with VerifySignature under sealdcrypto.LabelApproval and the approver's device key, then
// compares the approval with the very request it holds.
func ReadApprovalBody(body []byte) (ApprovalBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return ApprovalBody{}, err
	}
	b, err := bodies.ReadApproval(v)
	if err != nil {
		return ApprovalBody{}, err
	}
	return ApprovalBody(b), nil
}

// ReadInvitationBody reads an invitation: invitation_id, tenant_id, email_hash, roles, vendor_id where
// it names one, setup_code_hash where there is one, and expires_at. It names no key, so every check
// refuses malformed: bytes that are not canonical JSON, and a member missing, one its row does not name,
// or one in another form, a role empty or named twice among them, each member's form in that order.
//
// It reads the body and nothing of who signed it. The caller verifies the signature over these very
// bytes first, with VerifySignature under sealdcrypto.LabelInvitation and the inviter's device key.
// Whether it has expired is the caller's to check against its own clock.
func ReadInvitationBody(body []byte) (InvitationBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return InvitationBody{}, err
	}
	b, err := bodies.ReadInvitation(v)
	if err != nil {
		return InvitationBody{}, err
	}
	return InvitationBody(b), nil
}

// ReadRegistrationBody reads a backup key's registration: tenant_id, public_key, an x-wing key, and
// fingerprint. It refuses malformed a fingerprint that is not public_key's key digest, checked over the
// key as written, its algorithm's name as text and its value as written, before its algorithm and its
// import, so a key of an algorithm v1 does not have, or a value its import refuses, is refused for its
// fingerprint first, and invalid-key only under its own.
func ReadRegistrationBody(body []byte) (RegistrationBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return RegistrationBody{}, err
	}
	b, err := bodies.ReadRegistration(v)
	if err != nil {
		return RegistrationBody{}, err
	}
	return RegistrationBody(b), nil
}

// DeviceCallBody is a call a device key with no card yet makes about its own request, before its first
// session, what it signs under device-call.
type DeviceCallBody struct {
	// TenantID is the tenant the device enrols in.
	TenantID sealdcrypto.TenantID
	// Method is the call's HTTP method, a token of RFC 9110 in upper case.
	Method string
	// Path is the call's path and query exactly as sent, without the scheme and the host, beginning
	// with /. Nothing else of it is checked.
	Path string
	// BodyHash is the SHA-256 of the call's body as sent, over the empty body where it has none.
	BodyHash []byte
	// At is when the device signed the call, in UTC and whole seconds.
	At time.Time
}

// UnlockBody is a fresh unlock: what a device key signs under unlock where its client signs it, and
// what the unlock challenge, which a passkey asserts over, commits to wherever the unlock is made.
type UnlockBody struct {
	// TenantID is the tenant the unlock is in.
	TenantID sealdcrypto.TenantID
	// UnlockID is the unlock's id, drawn by the server.
	UnlockID sealdcrypto.UUID
	// Nonce is the nonce the server drew for the unlock, its 32 bytes. That it is the one the server
	// drew for this unlock, unspent, is the server's to compare.
	Nonce []byte
	// Requests are the requests the unlock approves, at least one, in the order the client asked for
	// them, none naming a request id twice.
	Requests []UnlockBodyRequest
	// ExpiresAt is when the unlock expires, in UTC and whole seconds.
	ExpiresAt time.Time
}

// UnlockBodyRequest is one request an unlock approves.
type UnlockBodyRequest struct {
	// RequestID is the id the client drew for the request it will send.
	RequestID sealdcrypto.UUID
	// Method is the request's HTTP method, a token of RFC 9110 in upper case.
	Method string
	// Path is the request's path and query exactly as sent, beginning with /.
	Path string
	// BodyHash is the SHA-256 of the request's body as sent, over the empty body where it has none.
	BodyHash []byte
}

// EpochBody is a key domain's new epoch, what a member's device key signs under epoch.
type EpochBody struct {
	TenantID sealdcrypto.TenantID
	// Root is the key domain root's locator, never empty.
	Root sealdcrypto.Locator
	// Epoch is the new epoch, from 1.
	Epoch uint64
	// KeyDigest is the key digest of the new epoch's domain key, over its x-wing public value, 32
	// bytes, read for its form alone, since the body holds no key. Every device that unwraps the epoch's
	// key, from a slice with open.UnwrapDomainKey or through a link, checks the key against it, so it is
	// taken from a body whose signature the caller verified, never from beside a wrap.
	KeyDigest []byte
	// EventID is the id the server gave the access event.
	EventID sealdcrypto.UUID
	// BackupFingerprint is the registered backup key's fingerprint, 32 bytes, read for its form alone:
	// that it is the registered key's is the caller's to compare.
	BackupFingerprint []byte
	// SlicesHash is the JSON hash of the commit's slices, backup slice and links, 32 bytes, which the
	// caller compares with the JSON hash of what the request carries.
	SlicesHash []byte
}

// EscrowCommitBody is a commit on a key domain's escrow, one body that a device key signs under share,
// backfill, join or delegation, which the label in the signed message tells apart.
type EscrowCommitBody struct {
	TenantID sealdcrypto.TenantID
	// Root is the key domain root's locator, never empty.
	Root sealdcrypto.Locator
	// EscrowVersion is the escrow version the slices were made against, from 1.
	EscrowVersion uint64
	// EventID is the id the server gave the access event.
	EventID sealdcrypto.UUID
	// SlicesHash is the JSON hash of the commit's slices, 32 bytes, which the caller compares with the
	// JSON hash of what the request carries.
	SlicesHash []byte
}

// RecordRecipientCommitBody is a record recipient's commit, the slices of one person on the envelope of
// a record's current version, which a device key signs under share or backfill.
type RecordRecipientCommitBody struct {
	TenantID sealdcrypto.TenantID
	// Locator is the record's, never empty.
	Locator sealdcrypto.Locator
	// Person is the record recipient's person hash, 32 bytes.
	Person []byte
	// EventID is the id the server gave the access event.
	EventID sealdcrypto.UUID
	// SlicesHash is the JSON hash of the commit's slices, 32 bytes, which the caller compares with the
	// JSON hash of the slices the request carries.
	SlicesHash []byte
}

// TokenisationKeyBackfillBody is the tokenisation key's backfill to a new card, a body a device key that
// holds the tenant's tokenisation key signs under backfill.
type TokenisationKeyBackfillBody struct {
	TenantID sealdcrypto.TenantID
	// RecipientID is the card the tokenisation key is wrapped to.
	RecipientID sealdcrypto.RecipientID
	// EventID is the id the server gave the access event.
	EventID sealdcrypto.UUID
	// WrapsHash is the JSON hash of the request's wraps, each wrapped as its text, 32 bytes, which the
	// caller compares with the JSON hash of the wraps the request carries, never re-encoded.
	WrapsHash []byte
}

// OwnershipBody is a member of a key domain made an owner, what the domain owner's device key signs
// under ownership. Ownership rewrites no escrow, so the body names no escrow version, no event and no
// slices: it is not a commit on the escrow, and neither body is read as the other.
type OwnershipBody struct {
	TenantID sealdcrypto.TenantID
	// Root is the key domain root's locator, never empty.
	Root sealdcrypto.Locator
	// Person is the person hash of the member made an owner, 32 bytes, never the person's subject.
	Person []byte
}

// MoveBody is a move's commit, the rewrapped keys of every version of a record or a file, what the
// domain owner's device key signs under move.
type MoveBody struct {
	TenantID sealdcrypto.TenantID
	// Locator is the record's or the file's, never empty.
	Locator sealdcrypto.Locator
	// Root is the locator of the key domain the object moves to, never empty.
	Root sealdcrypto.Locator
	// EventID is the id the server gave the access event.
	EventID sealdcrypto.UUID
	// Epoch is the target's epoch the keys are wrapped to, from 1.
	Epoch uint64
	// SlicesHash is the JSON hash of the commit's versions, 32 bytes, which the caller compares with the
	// JSON hash of the versions the request carries.
	SlicesHash []byte
}

// CommitBody is a commit of a key domain's folder index, with the version each save of it saves where
// there is one, what the writer's device key signs under commit.
type CommitBody struct {
	TenantID sealdcrypto.TenantID
	// Root is the key domain root's locator, never empty.
	Root sealdcrypto.Locator
	// LeaseID is the id the server gave the commit lease.
	LeaseID sealdcrypto.UUID
	// EventIDs are the access events the commit completes, 1 to MaxCommitEvents, none twice, in the
	// order the commit lease names them, which the caller compares with the lease's, order included.
	EventIDs []sealdcrypto.UUID
	// Epoch is the key domain's epoch, from 1.
	Epoch uint64
	// CommitHash is the JSON hash of what the commit carries, its version envelopes among them where it
	// carries any, 32 bytes, which the caller compares with the JSON hash of what the request carries.
	CommitHash []byte
}

// ReadDeviceCallBody reads a call a device key with no card yet makes about its own request, before its
// first session, what it signs under device-call: tenant_id; method, RFC 9110's token with no letter
// from a to z; path, text beginning with /; body_hash, 32 bytes as bytes in JSON; and at, an instant.
// Every check refuses malformed: a member missing, one more, or one in another form.
//
// It reads the body and nothing of who signed it, nor of the call. A verifier rebuilds the body from the
// call itself, its method, path and query as received, the SHA-256 of its body, and the at the call
// carries, verifies the signature over those bytes with VerifySignature under
// sealdcrypto.LabelDeviceCall and the key the call's path names, and checks at against its own clock: a
// body read from bytes the caller sent proves nothing of the call it came with. Nothing here checks what
// the call is about: the label covers a call about the device's own request alone, never one about its
// card, so a verifier accepts the label only on a call about the device's own request.
func ReadDeviceCallBody(body []byte) (DeviceCallBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return DeviceCallBody{}, err
	}
	b, err := bodies.ReadDeviceCall(v)
	if err != nil {
		return DeviceCallBody{}, err
	}
	return DeviceCallBody(b), nil
}

// ReadUnlockBody reads a fresh unlock, what the device key signs under unlock: tenant_id; unlock_id;
// nonce, 32 bytes as bytes in JSON; requests, an array of at least one object, each of exactly
// request_id, method, path and body_hash, no request_id twice; and expires_at, an instant. Every check
// refuses malformed, each member's form in that order.
//
// It reads the body and nothing of who signed it. The server lays the body out, and the client rebuilds
// it from what it asked before the touch and compares it with the server's byte for byte, before it
// signs or asserts over it.
func ReadUnlockBody(body []byte) (UnlockBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return UnlockBody{}, err
	}
	b, err := bodies.ReadUnlock(v)
	if err != nil {
		return UnlockBody{}, err
	}
	requests := make([]UnlockBodyRequest, len(b.Requests))
	for i, r := range b.Requests {
		requests[i] = UnlockBodyRequest(r)
	}
	return UnlockBody{TenantID: b.TenantID, UnlockID: b.UnlockID, Nonce: b.Nonce, Requests: requests, ExpiresAt: b.ExpiresAt}, nil
}

// ReadEpochBody reads a key domain's new epoch, what a member's device key signs under epoch:
// tenant_id; root, the domain root's locator as non-empty text; epoch, an integer from 1; key_digest, 32
// bytes as bytes in JSON; event_id; backup_fingerprint and slices_hash, each 32 bytes as bytes in JSON,
// each read for its form in that order. Every check refuses malformed. key_digest is read for its form
// alone: the body holds no key, and each unwrap of the epoch's key checks it.
//
// It reads the body and nothing of who signed it, nor of the request it came with: the caller verifies
// the signature over these very bytes first, then compares the backup fingerprint with the registered
// backup key's and the slices hash with the JSON hash of the slices, backup slice and links the
// request carries, and keeps the key digest, which a device gives open.UnwrapDomainKey for every unwrap
// of the epoch's key.
func ReadEpochBody(body []byte) (EpochBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return EpochBody{}, err
	}
	b, err := bodies.ReadEpoch(v)
	if err != nil {
		return EpochBody{}, err
	}
	return EpochBody(b), nil
}

// ReadEscrowCommitBody reads a commit on a key domain's escrow, signed under share, backfill, join or
// delegation. Every refusal is malformed.
//
// The body names no label: verify its signature under the label the flow expects first, since a
// signature under one of the four proves nothing under another. Under share and backfill it reads a
// domain's commit alone, and refuses a record recipient's or the tokenisation key's.
func ReadEscrowCommitBody(body []byte) (EscrowCommitBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return EscrowCommitBody{}, err
	}
	b, err := bodies.ReadEscrowCommit(v)
	if err != nil {
		return EscrowCommitBody{}, err
	}
	return EscrowCommitBody(b), nil
}

// ReadTokenisationKeyBackfillBody reads the tokenisation key's backfill to a new card, signed under
// backfill by a device that holds the tokenisation key. Every refusal is malformed.
//
// It refuses backfill's other bodies, a domain's and a record recipient's. Verify the signature over
// these very bytes first, then compare the recipient id with the card the wraps are to, and the wraps
// hash with the JSON hash of the wraps the request carries.
func ReadTokenisationKeyBackfillBody(body []byte) (TokenisationKeyBackfillBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return TokenisationKeyBackfillBody{}, err
	}
	b, err := bodies.ReadTokenisationKeyBackfill(v)
	if err != nil {
		return TokenisationKeyBackfillBody{}, err
	}
	return TokenisationKeyBackfillBody(b), nil
}

// ReadRecordRecipientCommitBody reads a record recipient's commit, signed under share or backfill.
// Every refusal is malformed.
//
// It refuses the other bodies under those labels, a domain's escrow commit and the tokenisation key's
// backfill, and they refuse it. The body names no label: verify its signature over these very bytes
// under the label the flow expects first, then compare the locator, person and event with the request's,
// and the slices hash with the JSON hash of the slices the request carries.
func ReadRecordRecipientCommitBody(body []byte) (RecordRecipientCommitBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return RecordRecipientCommitBody{}, err
	}
	b, err := bodies.ReadRecordRecipientCommit(v)
	if err != nil {
		return RecordRecipientCommitBody{}, err
	}
	return RecordRecipientCommitBody(b), nil
}

// ReadOwnershipBody reads a member of a key domain made an owner, what the domain owner's device key
// signs under ownership: tenant_id; root, the domain root's locator as non-empty text; and person, the
// person hash, 32 bytes as bytes in JSON. Every check refuses malformed, each member's form in that
// order: a member missing, one more, or one in another form. The body holds no key.
//
// It reads the body and nothing of who signed it, nor of the request it came with. The verifier
// rebuilds the body from the tenant, the domain the request is about and the person hash of the person
// it names, and verifies the signature over those very bytes first, with VerifySignature under
// sealdcrypto.LabelOwnership and the key of a device of a domain owner. A signature under share, the
// label of a commit on the domain's escrow, proves nothing under ownership.
//
// The body names nothing fresh, so an owner who makes the same member an owner twice signs the same
// bytes twice, and a signature over it proves only that the owner once signed these members. That a
// request is new, and not one replayed, is the caller's to check by what the request came with, never
// by the body.
func ReadOwnershipBody(body []byte) (OwnershipBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return OwnershipBody{}, err
	}
	b, err := bodies.ReadOwnership(v)
	if err != nil {
		return OwnershipBody{}, err
	}
	return OwnershipBody(b), nil
}

// ReadMoveBody reads a move's commit, what the domain owner's device key signs under move: tenant_id;
// locator, the record's or the file's, and root, the target domain root's, each a locator as non-empty
// text; event_id; epoch, an integer from 1; and slices_hash, 32 bytes as bytes in JSON. Every check
// refuses malformed, each member's form in that order.
//
// It reads the body and nothing of who signed it: the caller verifies the signature over these very
// bytes first, with VerifySignature under sealdcrypto.LabelMove and the key of a device of a domain
// owner, then compares the locator and the root with the request's, the epoch with the target's current
// one and the slices hash with the JSON hash of the versions the request carries.
func ReadMoveBody(body []byte) (MoveBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return MoveBody{}, err
	}
	b, err := bodies.ReadMove(v)
	if err != nil {
		return MoveBody{}, err
	}
	return MoveBody(b), nil
}

// MaxCommitEvents is the most events one commit completes, a group of saves' among them.
const MaxCommitEvents = bodies.MaxCommitEvents

// ReadCommitBody reads a commit of a key domain's folder index, what the writer's device key signs
// under commit: tenant_id; root, the domain root's locator as non-empty text; lease_id; event_ids, an
// array of 1 to MaxCommitEvents event ids, none twice; epoch, an integer from 1; and commit_hash, 32
// bytes as bytes in JSON. Every check refuses malformed, an event_id in place of event_ids among them.
//
// It reads the body and nothing of who signed it: the caller verifies the signature over these very
// bytes first, then compares the lease, the epoch and the commit hash with the lease it gave, the
// domain's epoch and the JSON hash of what the request carries.
func ReadCommitBody(body []byte) (CommitBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return CommitBody{}, err
	}
	b, err := bodies.ReadCommit(v)
	if err != nil {
		return CommitBody{}, err
	}
	return CommitBody(b), nil
}

// RevocationPurpose is what a body under revocation asks for. It is read before any other member, and
// names the members the rest of the body holds, so a body signed for one purpose never passes for
// another.
type RevocationPurpose string

// The purposes of a body under revocation.
const (
	// RevocationPurposeRevokeDevice revokes the device RecipientID names, for Reason.
	RevocationPurposeRevokeDevice RevocationPurpose = bodies.PurposeRevokeDevice
	// RevocationPurposeRequestRotation asks the device RecipientID names, or every device in the tenant
	// where EveryDevice is true, to rotate its key.
	RevocationPurposeRequestRotation RevocationPurpose = bodies.PurposeRequestRotation
	// RevocationPurposeRemovePasskey removes the passkey PasskeyID names.
	RevocationPurposeRemovePasskey RevocationPurpose = bodies.PurposeRemovePasskey
	// RevocationPurposeOffboard offboards the person Person names.
	RevocationPurposeOffboard RevocationPurpose = bodies.PurposeOffboard
)

// RevocationReason is why a device is revoked, as its asker gives it.
type RevocationReason string

// The reasons a revocation gives.
const (
	RevocationReasonLost    RevocationReason = bodies.ReasonLost
	RevocationReasonStolen  RevocationReason = bodies.ReasonStolen
	RevocationReasonRetired RevocationReason = bodies.ReasonRetired
)

// RevocationBody is what the asker's device key signs under revocation: revoking a device, asking for a
// rotation, removing a passkey or offboarding a person, as Purpose names. Each member Purpose does not
// name is its zero value, so a caller switches on Purpose before it reads any other, and never reads a
// member of a purpose it did not expect.
type RevocationBody struct {
	Purpose RevocationPurpose
	// TenantID is the tenant the request is in.
	TenantID sealdcrypto.TenantID
	// RecipientID is the device revoked, under RevocationPurposeRevokeDevice, or the device asked to
	// rotate, under RevocationPurposeRequestRotation where EveryDevice is false, and nil otherwise.
	RecipientID *sealdcrypto.RecipientID
	// Reason is why the device is revoked, under RevocationPurposeRevokeDevice, and empty otherwise. It
	// is for the record alone.
	Reason RevocationReason
	// EveryDevice is true where a rotation is asked for every device in the tenant, under
	// RevocationPurposeRequestRotation in place of RecipientID. Whether the asker may ask it, an Owner
	// alone, is the caller's to check.
	EveryDevice bool
	// PasskeyID is the passkey removed, under RevocationPurposeRemovePasskey, and nil otherwise.
	PasskeyID *sealdcrypto.UUID
	// Person is the person hash of the person offboarded, 32 bytes, under RevocationPurposeOffboard, and
	// nil otherwise.
	Person []byte
}

// ReadRevocationBody reads what the asker's device key signs under revocation: purpose, read before any
// other member, then tenant_id, then the members its purpose names, each read for its form in this
// order. revoke-device holds recipient_id and reason, lost, stolen or retired; request-rotation holds
// recipient_id or every_device, the boolean true, one and never both; remove-passkey holds passkey_id,
// a UUID as text; and offboard holds person, 32 bytes as bytes in JSON. Every check refuses malformed: a purpose revocation does not
// name, whatever v1 has elsewhere, a member missing, one the purpose does not name, and one in another
// form. The body holds no key.
//
// It reads the body and nothing of who signed it. A caller verifies the signature over these very bytes
// first, with VerifySignature under sealdcrypto.LabelRevocation and the asker's device key, switches on
// Purpose, and then checks what the body names against what the asker may do: the tenant, and the
// device, passkey or person it names.
func ReadRevocationBody(body []byte) (RevocationBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return RevocationBody{}, err
	}
	b, err := bodies.ReadRevocation(v)
	if err != nil {
		return RevocationBody{}, err
	}
	return RevocationBody{
		Purpose: RevocationPurpose(b.Purpose), TenantID: b.TenantID, RecipientID: b.RecipientID, Reason: RevocationReason(b.Reason),
		EveryDevice: b.EveryDevice, PasskeyID: b.PasskeyID, Person: b.Person,
	}, nil
}

// PersonStatePurpose is what a body under person-state asks for, read before any other member.
type PersonStatePurpose string

// The purposes of a body under person-state.
const (
	PersonStatePurposeSuspend   PersonStatePurpose = bodies.PurposeSuspend
	PersonStatePurposeReinstate PersonStatePurpose = bodies.PurposeReinstate
)

// PersonStateBody is what an Owner's or Admin's device key signs under person-state: suspending a
// person or reinstating them.
type PersonStateBody struct {
	Purpose PersonStatePurpose
	// TenantID is the tenant the person is in.
	TenantID sealdcrypto.TenantID
	// Person is the person hash of the person suspended or reinstated, 32 bytes.
	Person []byte
}

// ReadPersonStateBody reads what an Owner's or Admin's device key signs under person-state: purpose,
// suspend or reinstate, read before any other member, then tenant_id and person, 32 bytes as bytes in
// JSON. Every check refuses malformed, a purpose person-state does not name among them, so an
// offboarding, which holds the same members under revocation, is never read as a suspension. The body
// holds no key.
//
// It reads the body and nothing of who signed it: the caller verifies the signature over these very
// bytes first, with VerifySignature under sealdcrypto.LabelPersonState, and checks that its signer may
// suspend or reinstate the person it names.
func ReadPersonStateBody(body []byte) (PersonStateBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return PersonStateBody{}, err
	}
	b, err := bodies.ReadPersonState(v)
	if err != nil {
		return PersonStateBody{}, err
	}
	return PersonStateBody{Purpose: PersonStatePurpose(b.Purpose), TenantID: b.TenantID, Person: b.Person}, nil
}

// PasskeyPurpose is what a body under passkey is signed for, read before any other member.
type PasskeyPurpose string

// The purposes of a body under passkey.
const (
	// PasskeyPurposeRegister registers a new passkey, whose key PasskeyKey holds.
	PasskeyPurposeRegister PasskeyPurpose = bodies.PurposeRegister
	// PasskeyPurposeSeal seals a device key under a passkey already registered, whose key the server
	// holds, so the body names none.
	PasskeyPurposeSeal PasskeyPurpose = bodies.PurposeSeal
)

// PasskeyBody is what the person's device key signs under passkey.
type PasskeyBody struct {
	Purpose PasskeyPurpose
	// TenantID is the tenant the person is in.
	TenantID sealdcrypto.TenantID
	// Person is the person hash, 32 bytes.
	Person []byte
	// CredentialID is the passkey's WebAuthn credential id, its bytes as signed, never empty.
	CredentialID []byte
	// PasskeyKey is the passkey's public key as WebAuthn registered it, its COSE bytes as signed, never
	// empty, under PasskeyPurposeRegister, and nil under PasskeyPurposeSeal. It is read as bytes alone:
	// it is not parsed as a COSE key, and is no PublicKey. That it and CredentialID are what WebAuthn
	// registered is the relying party's to check, never a reader's.
	PasskeyKey []byte
}

// ReadPasskeyBody reads what the person's device key signs under passkey: purpose, register or seal,
// read before any other member, then tenant_id, person, 32 bytes as bytes in JSON, credential_id, and
// for register passkey_key, each non-empty bytes in JSON, and nothing more read of either. Every check
// refuses malformed: a purpose passkey does not name, whatever v1 has elsewhere, a member missing, one
// the purpose does not name, a passkey_key under seal among them, and one in another form, an empty
// credential_id or passkey_key among them.
//
// It reads the body and nothing of who signed it. The registration's or the assertion's WebAuthn
// challenge is the passkey challenge PasskeyChallengePasskey gives over this body, so the caller
// verifies the device key's signature over these very bytes with VerifySignature under
// sealdcrypto.LabelPasskey, and checks the ceremony against that challenge.
func ReadPasskeyBody(body []byte) (PasskeyBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return PasskeyBody{}, err
	}
	b, err := bodies.ReadPasskey(v)
	if err != nil {
		return PasskeyBody{}, err
	}
	return PasskeyBody{Purpose: PasskeyPurpose(b.Purpose), TenantID: b.TenantID, Person: b.Person, CredentialID: b.CredentialID, PasskeyKey: b.PasskeyKey}, nil
}

// RolePurpose is what a body under role asks for, read before any other member, so a role given is
// never read as one removed, nor either as an Owner minimum.
type RolePurpose string

// The purposes of a body under role.
const (
	// RolePurposeGive gives the person Person names the role Role names.
	RolePurposeGive RolePurpose = bodies.PurposeGive
	// RolePurposeRemove removes the role Role names from the person Person names.
	RolePurposeRemove RolePurpose = bodies.PurposeRemove
	// RolePurposeSetOwnerMinimum asks for the tenant's Owner minimum OwnerMinimum names.
	RolePurposeSetOwnerMinimum RolePurpose = bodies.PurposeSetOwnerMinimum
)

// RoleBody is what a device key signs under role: the granter's, giving a person a role or removing
// one, or an Owner's, asking for the tenant's Owner minimum, as Purpose names. Each member Purpose does
// not name is its zero value, so a caller switches on Purpose before it reads any other, and never
// reads a member of a purpose it did not expect.
type RoleBody struct {
	Purpose RolePurpose
	// TenantID is the tenant the change is in.
	TenantID sealdcrypto.TenantID
	// Person is the person hash of the person given the role or removed from it, 32 bytes, under
	// RolePurposeGive and RolePurposeRemove, and nil otherwise.
	Person []byte
	// Role is the role's name as text, never empty, under RolePurposeGive and RolePurposeRemove, and
	// empty otherwise. It is read for its form alone and compared as written: which roles the tenant
	// has, and whether the signer may change this one, are the caller's to check.
	Role string
	// OwnerMinimum is the Owner minimum asked, from 1, under RolePurposeSetOwnerMinimum, and 0
	// otherwise. Whether the tenant has as many Owners, and whether a lowering waits for a second
	// Owner, are the caller's to check.
	OwnerMinimum uint64
}

// ReadRoleBody reads what a device key signs under role: purpose, give, remove or set-owner-minimum,
// read before any other member, then tenant_id, then the members its purpose names, each read for its
// form in this order. give and remove hold person, 32 bytes as bytes in JSON, and role, one role name
// as non-empty text; set-owner-minimum holds owner_minimum, an integer from 1. Every check refuses
// malformed: a purpose role does not name, whatever v1 has elsewhere, a member missing, one the purpose
// does not name, and one in another form. The body holds no key.
//
// It reads the body and nothing of who signed it. A caller verifies the signature over these very bytes
// first, with VerifySignature under sealdcrypto.LabelRole and the signer's device key, switches on
// Purpose, and checks that the signer may make the change: the granter for a role, an Owner for the
// Owner minimum.
func ReadRoleBody(body []byte) (RoleBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return RoleBody{}, err
	}
	b, err := bodies.ReadRole(v)
	if err != nil {
		return RoleBody{}, err
	}
	return RoleBody{Purpose: RolePurpose(b.Purpose), TenantID: b.TenantID, Person: b.Person, Role: b.Role, OwnerMinimum: b.OwnerMinimum}, nil
}

// AccountBody is what an Owner's or Admin's device key signs under account: an account's reset at the
// identity provider.
type AccountBody struct {
	// TenantID is the tenant the account is in.
	TenantID sealdcrypto.TenantID
	// Subject is the person's sub at the identity provider, as written, never empty.
	Subject string
	// SetupCodeHash is the secret hash of the new setup code the reset draws, 32 bytes.
	SetupCodeHash []byte
}

// ReadAccountBody reads what an Owner's or Admin's device key signs under account: tenant_id, subject,
// the person's sub as non-empty text, and setup_code_hash, 32 bytes as bytes in JSON, each read for its
// form in that order. Every check refuses malformed, and the body holds no key.
//
// It reads the body and nothing of who signed it. A caller verifies the signature over these very bytes
// first, with VerifySignature under sealdcrypto.LabelAccount, and checks that its signer may reset the
// account Subject names.
func ReadAccountBody(body []byte) (AccountBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return AccountBody{}, err
	}
	b, err := bodies.ReadAccount(v)
	if err != nil {
		return AccountBody{}, err
	}
	return AccountBody(b), nil
}

// AgentState is an AI agent's state, as a body under agent-state sets it.
type AgentState string

// The states a body under agent-state sets.
const (
	// AgentStatePaused pauses the agent, which its delegator signs.
	AgentStatePaused AgentState = bodies.AgentPaused
	// AgentStateFrozen freezes the agent, which an Owner or Admin signs.
	AgentStateFrozen AgentState = bodies.AgentFrozen
	// AgentStateActive lifts a pause, which the delegator signs, or a freeze, which an Owner or Admin
	// signs.
	AgentStateActive AgentState = bodies.AgentActive
)

// AgentStateBody is what a device key signs under agent-state: an AI agent paused, frozen, or made
// active again.
type AgentStateBody struct {
	// TenantID is the tenant the agent is in.
	TenantID sealdcrypto.TenantID
	// AgentID is the agent's id.
	AgentID sealdcrypto.UUID
	// State is the state set.
	State AgentState
}

// ReadAgentStateBody reads what a device key signs under agent-state: tenant_id, agent_id, a UUID as
// text, and state, paused, frozen or active, each read for its form in that order. Every check refuses
// malformed, and the body holds no key.
//
// It reads the body and nothing of who signed it. A caller verifies the signature over these very bytes
// first, with VerifySignature under sealdcrypto.LabelAgentState, and checks that its signer may set
// State: the agent's delegator for a pause and its end, an Owner or Admin for a freeze and its end.
func ReadAgentStateBody(body []byte) (AgentStateBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return AgentStateBody{}, err
	}
	b, err := bodies.ReadAgentState(v)
	if err != nil {
		return AgentStateBody{}, err
	}
	return AgentStateBody{TenantID: b.TenantID, AgentID: b.AgentID, State: AgentState(b.State)}, nil
}

// SessionManifestBody is a session's manifest, what the device key signs under manifest at the end of a
// session.
type SessionManifestBody struct {
	// TenantID is the tenant the session is in.
	TenantID sealdcrypto.TenantID
	// Events is the id of each access event the session read, in the order it read them, none twice,
	// and empty, not nil, where it read none.
	Events []sealdcrypto.UUID
}

// ReadSessionManifestBody reads a session's manifest, what the device key signs under manifest:
// tenant_id, and events, an array of event ids, each a UUID as text, none twice, and empty where the
// session read none, each read for its form in that order. Every check refuses malformed, and the body
// holds no key.
//
// An export's manifest is signed under manifest too, and is the evidence pack's own, laid out as the
// pack sets: this function never reads one, and a caller reads the body its request carries.
//
// It reads the body and nothing of who signed it. A caller verifies the signature over these very bytes
// first, with VerifySignature under sealdcrypto.LabelManifest and the session's device key, and checks
// that each event is one the session read.
func ReadSessionManifestBody(body []byte) (SessionManifestBody, error) {
	v, err := canonical.ParseJSON(body)
	if err != nil {
		return SessionManifestBody{}, err
	}
	b, err := bodies.ReadSessionManifest(v)
	if err != nil {
		return SessionManifestBody{}, err
	}
	return SessionManifestBody(b), nil
}

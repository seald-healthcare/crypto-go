package sealdcrypto

// Label is what a signature is made under, so a signature under one label never verifies under
// another. sign.Sign and verify.VerifySignature refuse any label v1 does not have unsupported, so a
// label read from a wire needs no check of its own.
type Label string

// The labels v1 has. Where a body is read under a label, its reader is named.
const (
	// LabelSession: verify.ReadSessionBody, and an opening's App Attest challenge verify.AppAttestChallenge.
	LabelSession Label = "session"
	// LabelEnrolment: verify.ReadEnrolmentRequestBody, or verify.ReadRotationRequestBody at a rotation.
	LabelEnrolment Label = "enrolment"
	// LabelDeviceCall: verify.ReadDeviceCallBody. Verify the signature over the body rebuilt from the
	// call itself, never over one the caller sent.
	LabelDeviceCall Label = "device-call"
	LabelApproval   Label = "approval"
	// LabelRotation: verify.ReadRotationRequestBody.
	LabelRotation   Label = "rotation"
	LabelInvitation Label = "invitation"
	// LabelAccount: verify.ReadAccountBody.
	LabelAccount  Label = "account"
	LabelEnvelope Label = "envelope"
	// LabelCommit: verify.ReadCommitBody.
	LabelCommit Label = "commit"
	// LabelShare: verify.ReadEscrowCommitBody, or verify.ReadRecordRecipientCommitBody for a record
	// recipient's commit. Read the body the request carries; no reader takes another's.
	LabelShare Label = "share"
	// LabelOwnership: verify.ReadOwnershipBody.
	LabelOwnership Label = "ownership"
	// LabelMove: verify.ReadMoveBody.
	LabelMove Label = "move"
	// LabelBackfill: verify.ReadEscrowCommitBody, verify.ReadRecordRecipientCommitBody for a record's
	// backfill, or verify.ReadTokenisationKeyBackfillBody for the tokenisation key's. Read the body the
	// request carries; no reader takes another's.
	LabelBackfill Label = "backfill"
	// LabelJoin: verify.ReadEscrowCommitBody.
	LabelJoin Label = "join"
	// LabelEpoch: verify.ReadEpochBody.
	LabelEpoch Label = "epoch"
	// LabelManifest: verify.ReadSessionManifestBody. An export's manifest is read by no reader here.
	LabelManifest Label = "manifest"
	LabelOffline  Label = "offline"
	// LabelRole: verify.ReadRoleBody.
	LabelRole   Label = "role"
	LabelPolicy Label = "policy"
	LabelGrant  Label = "grant"
	LabelAgent  Label = "agent"
	// LabelAgentState: verify.ReadAgentStateBody.
	LabelAgentState Label = "agent-state"
	// LabelDelegation: verify.ReadEscrowCommitBody.
	LabelDelegation Label = "delegation"
	LabelVendor     Label = "vendor"
	// LabelRevocation: verify.ReadRevocationBody.
	LabelRevocation Label = "revocation"
	// LabelPersonState: verify.ReadPersonStateBody.
	LabelPersonState Label = "person-state"
	// LabelPasskey: verify.ReadPasskeyBody, whose WebAuthn challenge verify.PasskeyChallengePasskey gives.
	LabelPasskey Label = "passkey"
	// LabelUnlock: verify.ReadUnlockBody, whose challenge verify.UnlockChallenge gives.
	LabelUnlock Label = "unlock"
	// LabelRecovery: verify.ReadRecoveryBody.
	LabelRecovery Label = "recovery"
	// LabelRegistration: verify.ReadRegistrationBody.
	LabelRegistration Label = "registration"
	// LabelCard: a certificate sign.Certify makes and verify.VerifyCard checks.
	LabelCard Label = "card"
	// LabelBackupKey: the identity authority's signature over verify.Tuple of a registration's bytes and
	// the minting device's signature value.
	LabelBackupKey Label = "backup-key"
	// LabelIdentityAuthority: a certificate sign.Certify makes and verify.VerifyIdentityAuthority checks.
	LabelIdentityAuthority Label = "identity-authority"
)

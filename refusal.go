package sealdcrypto

// RefusalKind is why bytes from a wire or from storage were refused, as its text. Treat a kind you do
// not know as a refusal still, never as success.
type RefusalKind string

// The kinds of refusal.
const (
	RefusalKindMalformed            RefusalKind = "malformed"
	RefusalKindUnsupported          RefusalKind = "unsupported"
	RefusalKindInvalidKey           RefusalKind = "invalid-key"
	RefusalKindAuthenticationFailed RefusalKind = "authentication-failed"
	RefusalKindSignatureInvalid     RefusalKind = "signature-invalid"
	RefusalKindTenantMismatch       RefusalKind = "tenant-mismatch"
	RefusalKindPersonMismatch       RefusalKind = "person-mismatch"
	RefusalKindOutsideWindow        RefusalKind = "outside-window"
	RefusalKindOutOfRange           RefusalKind = "out-of-range"
	RefusalKindPhraseMismatch       RefusalKind = "phrase-mismatch"
	RefusalKindTimestampInvalid     RefusalKind = "timestamp-invalid"
)

// Refusal is the error returned, found with errors.As, for bytes from a wire or from storage that fail;
// a panic is the caller's own mistake. Decide on Kind alone.
type Refusal struct {
	Kind RefusalKind
	// Detail is a fixed phrase for logs that never quotes the input, a secret or a plaintext, so a
	// refusal may be logged whole. Its wording may change in any release.
	Detail string
}

// Error is the kind, then the detail: "sealdcrypto: malformed: trailing bytes".
func (r *Refusal) Error() string {
	if r.Detail == "" {
		return "sealdcrypto: " + string(r.Kind)
	}
	return "sealdcrypto: " + string(r.Kind) + ": " + r.Detail
}

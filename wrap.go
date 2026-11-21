package sealdcrypto

// WrapContext is a wrap's purpose and the identifiers it is bound to, one of the WrapContext structs
// passed by value. Name the context you expect from what you are opening, never one read from the wrap.
// A nil context or a pointer is a fault.
type WrapContext interface {
	wrapContext()
}

// SecretWrapContext is a context whose secret is used as its bytes, which open.Unwrap and
// open.UnwrapWith take, so no domain key is unwrapped without its key digest.
type SecretWrapContext interface {
	WrapContext
	secretWrapContext()
}

// DomainKeyWrapContext is a context whose secret is a domain key's X-Wing seed, which only
// open.UnwrapDomainKey and open.UnwrapDomainKeyWith take, each with the epoch's key digest.
type DomainKeyWrapContext interface {
	WrapContext
	domainKeyWrapContext()
}

// WrapContextContentKey is purpose content-key. An empty Locator is a fault.
type WrapContextContentKey struct {
	Tenant  TenantID
	Locator Locator
	Version uint64
	Segment string
}

// WrapContextDomainKey is purpose domain-key. An empty DomainRoot and an Epoch below 1 are faults.
type WrapContextDomainKey struct {
	Tenant     TenantID
	DomainRoot Locator
	Epoch      uint64
}

// WrapContextEpochLink is purpose epoch-link: LinkedEpoch's key wrapped to Epoch's. An empty DomainRoot,
// an epoch below 1 and a LinkedEpoch not below Epoch are faults. It opens under LinkedEpoch's key digest.
type WrapContextEpochLink struct {
	Tenant      TenantID
	DomainRoot  Locator
	LinkedEpoch uint64
	Epoch       uint64
}

// WrapContextTokenisationKey is purpose tokenisation-key. Name the epoch an event or a ref names, never
// one the wrap's sender gives. An Epoch below 1 is a fault.
type WrapContextTokenisationKey struct {
	Tenant TenantID
	Epoch  uint64
}

// WrapContextRefoundingChallenge is purpose refounding-challenge: a re-founding's challenge, wrapped to
// the tenant's backup key. Refounding is the id the re-founding was given.
type WrapContextRefoundingChallenge struct {
	Tenant     TenantID
	Refounding UUID
}

func (WrapContextContentKey) wrapContext()          {}
func (WrapContextDomainKey) wrapContext()           {}
func (WrapContextEpochLink) wrapContext()           {}
func (WrapContextTokenisationKey) wrapContext()     {}
func (WrapContextRefoundingChallenge) wrapContext() {}

func (WrapContextContentKey) secretWrapContext()          {}
func (WrapContextTokenisationKey) secretWrapContext()     {}
func (WrapContextRefoundingChallenge) secretWrapContext() {}

func (WrapContextDomainKey) domainKeyWrapContext() {}
func (WrapContextEpochLink) domainKeyWrapContext() {}

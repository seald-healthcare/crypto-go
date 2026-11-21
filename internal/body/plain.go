package body

import (
	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
)

// The bodies under account, agent-state and manifest hold no purpose and no key, so each is read for
// its members' forms alone, in the order its row names them, and every check refuses malformed (the
// Crypto API, Bodies).

// Account is an account's reset at the identity provider, under account: the tenant, the person's
// subject at the identity provider, and the secret hash of the setup code the reset draws.
type Account struct {
	TenantID      sealdcrypto.TenantID
	Subject       string
	SetupCodeHash []byte
}

// ReadAccount reads a body under account: tenant_id, subject, the person's sub as non-empty text, and
// setup_code_hash, 32 bytes, each read for its form in that order, every check malformed. The subject
// is read as written and compared as written: that it names a person of the tenant is the caller's.
func ReadAccount(v sealdcrypto.JSON) (Account, error) {
	m, err := members(v, []string{"tenant_id", "subject", "setup_code_hash"})
	if err != nil {
		return Account{}, err
	}
	var a Account
	if a.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return Account{}, err
	}
	if a.Subject, err = textOf(m, "subject"); err != nil {
		return Account{}, err
	}
	if a.Subject == "" {
		return Account{}, refusal.New(sealdcrypto.RefusalKindMalformed, "a body naming an empty subject")
	}
	if a.SetupCodeHash, err = bytesOf(m, "setup_code_hash", HashSize); err != nil {
		return Account{}, err
	}
	return a, nil
}

// An AI agent's states, as a body under agent-state names them (the Crypto API, Bodies, state).
const (
	AgentPaused = "paused"
	AgentFrozen = "frozen"
	AgentActive = "active"
)

// AgentState is an AI agent's state set, under agent-state: the tenant, the agent's id, and the state,
// paused, frozen or active.
type AgentState struct {
	TenantID sealdcrypto.TenantID
	AgentID  sealdcrypto.UUID
	State    string
}

// ReadAgentState reads a body under agent-state: tenant_id, agent_id, a UUID as text, and state,
// paused, frozen or active, each read for its form in that order, every check malformed. Who may sign
// which state, the delegator or an Owner or Admin, is the caller's to check against the signer.
func ReadAgentState(v sealdcrypto.JSON) (AgentState, error) {
	m, err := members(v, []string{"tenant_id", "agent_id", "state"})
	if err != nil {
		return AgentState{}, err
	}
	var a AgentState
	if a.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return AgentState{}, err
	}
	if a.AgentID, err = uuidOf(m, "agent_id"); err != nil {
		return AgentState{}, err
	}
	if a.State, err = textOf(m, "state"); err != nil {
		return AgentState{}, err
	}
	if a.State != AgentPaused && a.State != AgentFrozen && a.State != AgentActive {
		return AgentState{}, refusal.New(sealdcrypto.RefusalKindMalformed, "an agent's state that is not paused, frozen or active")
	}
	return a, nil
}

// SessionManifest is a session's manifest, under manifest: the tenant, and the id of each access event
// the session read, in the order it read them. An export's manifest, the other body signed under
// manifest, is laid out by the evidence pack, and no reader here reads it.
type SessionManifest struct {
	TenantID sealdcrypto.TenantID
	Events   []sealdcrypto.UUID
}

// ReadSessionManifest reads a session's manifest: tenant_id, and events, an array of event ids, each a
// UUID as text, none twice, and empty where the session read none, each read for its form in that
// order, every check malformed. An event named twice is the member's own form, so it is checked as
// events is read. Events is empty, and not nil, where the body names none.
func ReadSessionManifest(v sealdcrypto.JSON) (SessionManifest, error) {
	m, err := members(v, []string{"tenant_id", "events"})
	if err != nil {
		return SessionManifest{}, err
	}
	var s SessionManifest
	if s.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return SessionManifest{}, err
	}
	list, ok := m["events"].([]any)
	if !ok {
		return SessionManifest{}, notOfItsForm
	}
	s.Events = make([]sealdcrypto.UUID, 0, len(list))
	// seen keeps the check linear in the events, however many a manifest names.
	seen := make(map[sealdcrypto.UUID]bool, len(list))
	for _, e := range list {
		text, ok := e.(string)
		if !ok {
			return SessionManifest{}, refusal.New(sealdcrypto.RefusalKindMalformed, "a body's member that is not text")
		}
		id, err := sealdcrypto.ParseUUID(text)
		if err != nil {
			return SessionManifest{}, err
		}
		if seen[id] {
			return SessionManifest{}, refusal.New(sealdcrypto.RefusalKindMalformed, "a manifest naming an event twice")
		}
		seen[id] = true
		s.Events = append(s.Events, id)
	}
	return s, nil
}

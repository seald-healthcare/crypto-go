package body

import (
	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
)

// Recovery is a key recovery's ask or commit. A member its purpose does not name is the zero value.
type Recovery struct {
	Purpose    string
	TenantID   sealdcrypto.TenantID
	Domains    []sealdcrypto.Locator
	AllDomains bool
	Person     []byte
	ReasonCode string
	Reference  string
	RecoveryID sealdcrypto.UUID
	SlicesHash []byte
}

// ReadRecovery reads a key recovery's ask or commit. A reason code and a reference are read for their
// form alone.
func ReadRecovery(v sealdcrypto.JSON) (Recovery, error) {
	purpose, err := purposeOf(sealdcrypto.LabelRecovery, v)
	if err != nil {
		return Recovery{}, err
	}
	required := []string{"purpose", "tenant_id", "person", "reason_code", "reference"}
	optional := []string{"domains", "all_domains"}
	if purpose == PurposeCommit {
		required, optional = []string{"purpose", "tenant_id", "recovery_id", "slices_hash"}, nil
	}
	m, err := members(v, required, optional...)
	if err != nil {
		return Recovery{}, err
	}
	r := Recovery{Purpose: purpose}
	if r.TenantID, err = uuidOf(m, "tenant_id"); err != nil {
		return Recovery{}, err
	}
	if purpose == PurposeCommit {
		if r.RecoveryID, err = uuidOf(m, "recovery_id"); err != nil {
			return Recovery{}, err
		}
		if r.SlicesHash, err = bytesOf(m, "slices_hash", HashSize); err != nil {
			return Recovery{}, err
		}
		return r, nil
	}
	if r.Domains, r.AllDomains, err = domainsOrAll(m); err != nil {
		return Recovery{}, err
	}
	if r.Person, err = bytesOf(m, "person", HashSize); err != nil {
		return Recovery{}, err
	}
	if r.ReasonCode, err = textOf(m, "reason_code"); err != nil {
		return Recovery{}, err
	}
	if r.ReasonCode == "" {
		return Recovery{}, refusal.New(sealdcrypto.RefusalKindMalformed, "a body naming an empty reason code")
	}
	if r.Reference, err = textOf(m, "reference"); err != nil {
		return Recovery{}, err
	}
	return r, nil
}

// domainsOrAll reads domains or all_domains, refusing both or neither at domains' place in the order.
func domainsOrAll(m map[string]any) (domains []sealdcrypto.Locator, allDomains bool, err error) {
	_, named := m["domains"]
	_, every := m["all_domains"]
	switch {
	case named && every:
		return nil, false, refusal.New(sealdcrypto.RefusalKindMalformed, "a body naming domains and every domain")
	case named:
		domains, err = domainsOf(m, "domains")
		return domains, false, err
	case every:
		if m["all_domains"] != true {
			return nil, false, refusal.New(sealdcrypto.RefusalKindMalformed, "an all_domains that is not true")
		}
		return nil, true, nil
	default:
		return nil, false, refusal.New(sealdcrypto.RefusalKindMalformed, "a body, or an object in it, with a member missing")
	}
}

// domainsOf reads at least one root, none twice, compared as written, in the body's order.
func domainsOf(m map[string]any, name string) ([]sealdcrypto.Locator, error) {
	list, ok := m[name].([]any)
	if !ok {
		return nil, notOfItsForm
	}
	if len(list) == 0 {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "a body naming no domain")
	}
	domains := make([]sealdcrypto.Locator, 0, len(list))
	// seen keeps the check linear in the roots, however many a body names.
	seen := make(map[sealdcrypto.Locator]bool, len(list))
	for _, v := range list {
		root, err := locatorOf(map[string]any{name: v}, name)
		if err != nil {
			return nil, err
		}
		if seen[root] {
			return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "a body naming a domain twice")
		}
		seen[root] = true
		domains = append(domains, root)
	}
	return domains, nil
}

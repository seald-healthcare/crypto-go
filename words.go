package sealdcrypto

// UUID is a UUID's 16 bytes. Read text from a wire or from storage with ParseUUID, never with another
// library's parser, which accepts forms this library refuses, such as upper case.
type UUID [16]byte

// ParseUUID reads RFC 9562's text of a UUID in lower case, and refuses any other form malformed, so
// one UUID has one text.
func ParseUUID(text string) (UUID, error) {
	var u UUID
	if len(text) != 36 {
		return UUID{}, malformedUUID()
	}
	for i, j := 0, 0; i < len(text); {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if text[i] != '-' {
				return UUID{}, malformedUUID()
			}
			i++
			continue
		}
		hi, ok1 := lowerHex(text[i])
		lo, ok2 := lowerHex(text[i+1])
		if !ok1 || !ok2 {
			return UUID{}, malformedUUID()
		}
		u[j] = hi<<4 | lo
		i, j = i+2, j+1
	}
	return u, nil
}

func lowerHex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

func malformedUUID() *Refusal {
	return &Refusal{Kind: RefusalKindMalformed, Detail: "a UUID that is not RFC 9562's text in lower case"}
}

// String is the UUID's RFC 9562 text in lower case.
func (u UUID) String() string {
	const digits = "0123456789abcdef"
	b := make([]byte, 0, 36)
	for i, c := range u {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			b = append(b, '-')
		}
		b = append(b, digits[c>>4], digits[c&0x0f])
	}
	return string(b)
}

// TenantID is a tenant's id. Nothing checks that a UUID given as one names a tenant.
type TenantID = UUID

// RecipientID is the first 16 bytes of a key's digest. It names a key and never proves one, so a
// caller checks the key against it.
type RecipientID [16]byte

// Locator is the opaque id of a record, file, folder index or key domain root, a type of its own so no
// other text passes for one. An empty locator is a fault wherever the caller gives one to seal or wrap.
type Locator string

// JSON is a JSON value as encoding/json decodes into an any: nil, bool, string, float64, the integer
// types, []any or map[string]any. A nil slice or map is empty; only nil is null. Any other type, such as
// []string or a defined string type, is a fault, so convert it first. Returned values hold int64.
type JSON = any

// Person is a person as the identity provider names them. Sub is the value of the claim the tenant names
// its people by, which need not be the provider's sub claim.
type Person struct {
	Iss string
	Sub string
}

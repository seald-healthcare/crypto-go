// Package canonical is the contract's canonical JSON, which verify, sign and open each compose: RFC 8785
// over the JSON Seald writes, which holds strings, booleans, null, arrays, objects and integers of
// magnitude below 2^53 (the Crypto API, Encoding).
//
// RFC 8785 itself is encoding/json/jsontext's Value.Canonicalize, which RFC 8785's vectors hold. This
// package adds what Seald's JSON refuses beyond it, and the value in Go a JSON text reads as.
package canonical

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"math"
	"strconv"
	"unicode/utf8"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
)

// limit is the magnitude every integer of Seald's JSON stays below: 2^53, past which a double, as
// RFC 8785 reads every number, no longer holds each integer.
const limit = 1 << 53

// maxDepth is how deep arrays and objects nest, as the contract's Encoding sets: [] and {} are depth 1,
// and each array or object inside another adds one. A value is refused past it as a text is, so every
// implementation reads what any other writes, and a cycle in a value reaches it rather than the end of
// the stack.
const maxDepth = 64

// JSON is value's canonical JSON. value holds only nil, bool, string, float64, the integer types,
// []any and map[string]any, which is also what encoding/json decodes into an any, and a nil slice or
// map is empty. Any other type is a fault: it panics.
//
// It refuses malformed a float64 that is a fraction or not finite, an integer of magnitude 2^53 or
// more, text that is not well-formed Unicode, and arrays and objects nested more than 64 deep.
func JSON(value any) ([]byte, error) {
	b, err := appendValue(nil, value, 0)
	if err != nil {
		return nil, err
	}
	v := jsontext.Value(b)
	// jsontext's error quotes the text, so it is never passed on. Every refusal it could make was made
	// above, so none is expected here.
	if v.Canonicalize() != nil {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "not JSON")
	}
	return v, nil
}

func appendValue(b []byte, value any, depth int) ([]byte, error) {
	switch v := value.(type) {
	case nil:
		return append(b, "null"...), nil
	case bool:
		return strconv.AppendBool(b, v), nil
	case string:
		return appendString(b, v)
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || v != math.Trunc(v) {
			return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "a number that is not an integer")
		}
		if math.Abs(v) >= limit {
			return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "an integer of magnitude 2^53 or more")
		}
		return strconv.AppendInt(b, int64(v), 10), nil
	case int:
		return appendInt(b, int64(v))
	case int8:
		return appendInt(b, int64(v))
	case int16:
		return appendInt(b, int64(v))
	case int32:
		return appendInt(b, int64(v))
	case int64:
		return appendInt(b, v)
	case uint:
		return appendUint(b, uint64(v))
	case uint8:
		return appendUint(b, uint64(v))
	case uint16:
		return appendUint(b, uint64(v))
	case uint32:
		return appendUint(b, uint64(v))
	case uint64:
		return appendUint(b, v)
	case []any:
		if depth++; depth > maxDepth {
			return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "nested too deep")
		}
		b = append(b, '[')
		for i, e := range v {
			if i > 0 {
				b = append(b, ',')
			}
			var err error
			if b, err = appendValue(b, e, depth); err != nil {
				return nil, err
			}
		}
		return append(b, ']'), nil
	case map[string]any:
		if depth++; depth > maxDepth {
			return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "nested too deep")
		}
		b = append(b, '{')
		first := true
		// Canonicalize orders the members, so the map's order does not matter here.
		for name, e := range v {
			if !first {
				b = append(b, ',')
			}
			first = false
			var err error
			if b, err = appendString(b, name); err != nil {
				return nil, err
			}
			b = append(b, ':')
			if b, err = appendValue(b, e, depth); err != nil {
				return nil, err
			}
		}
		return append(b, '}'), nil
	default:
		panic("canonicalJson: a value of a type JSON does not hold")
	}
}

func appendString(b []byte, s string) ([]byte, error) {
	if !utf8.ValidString(s) {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "text that is not well-formed Unicode")
	}
	b, err := jsontext.AppendQuote(b, s)
	if err != nil {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "text that is not well-formed Unicode")
	}
	return b, nil
}

func appendInt(b []byte, v int64) ([]byte, error) {
	if v <= -limit || v >= limit {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "an integer of magnitude 2^53 or more")
	}
	return strconv.AppendInt(b, v, 10), nil
}

func appendUint(b []byte, v uint64) ([]byte, error) {
	if v >= limit {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "an integer of magnitude 2^53 or more")
	}
	return strconv.AppendUint(b, v, 10), nil
}

// ParseJSON is the value of b, where b is canonical: the bytes JSON writes for the value it reads as,
// and nothing else. It refuses malformed bytes that are not JSON, hold a duplicate member or text that
// is not well-formed Unicode, nest arrays and objects more than 64 deep, or are not canonical, which
// includes a fraction and an integer of magnitude 2^53 or more, since JSON writes neither. The depth
// is measured before any parser reads b, so no text from a wire reaches one nested deeper.
//
// The value holds nil, bool, string, int64, []any and map[string]any alone.
func ParseJSON(b []byte) (any, error) {
	if tooDeep(b) {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "nested too deep")
	}
	v := jsontext.Value(bytes.Clone(b))
	if v.Canonicalize() != nil {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "not JSON")
	}
	if !bytes.Equal(v, b) {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "not canonical")
	}
	d := jsontext.NewDecoder(bytes.NewReader(b))
	value, err := readValue(d)
	if err != nil {
		return nil, err
	}
	return value, nil
}

// tooDeep is whether b opens an array or object more than maxDepth deep, outside its strings. It is
// exact for JSON, and b that is not JSON is refused either way.
func tooDeep(b []byte) bool {
	depth, inString, escaped := 0, false, false
	for _, c := range b {
		switch {
		case escaped:
			escaped = false
		case inString:
			switch c {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
		case c == '"':
			inString = true
		case c == '[' || c == '{':
			if depth++; depth > maxDepth {
				return true
			}
		case c == ']' || c == '}':
			depth--
		}
	}
	return false
}

// readValue reads one value from d, whose text Canonicalize has already read whole, so no read fails
// but at a number Seald's JSON does not hold.
func readValue(d *jsontext.Decoder) (any, error) {
	t, err := d.ReadToken()
	if err != nil {
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "not JSON")
	}
	switch t.Kind() {
	case 'n':
		return nil, nil
	case 't', 'f':
		return t.Bool(), nil
	case '"':
		return t.String(), nil
	case '0':
		n, err := t.Int()
		if errors.Is(err, strconv.ErrSyntax) {
			return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "a number that is not an integer")
		}
		if err != nil || n <= -limit || n >= limit {
			return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "an integer of magnitude 2^53 or more")
		}
		return n, nil
	case '[':
		a := []any{}
		for d.PeekKind() != ']' {
			e, err := readValue(d)
			if err != nil {
				return nil, err
			}
			a = append(a, e)
		}
		if _, err := d.ReadToken(); err != nil {
			return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "not JSON")
		}
		return a, nil
	case '{':
		o := map[string]any{}
		for d.PeekKind() != '}' {
			name, err := d.ReadToken()
			if err != nil {
				return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "not JSON")
			}
			key := name.String()
			e, err := readValue(d)
			if err != nil {
				return nil, err
			}
			o[key] = e
		}
		if _, err := d.ReadToken(); err != nil {
			return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "not JSON")
		}
		return o, nil
	default:
		return nil, refusal.New(sealdcrypto.RefusalKindMalformed, "not JSON")
	}
}

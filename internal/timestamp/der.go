package timestamp

import (
	"bytes"
	"encoding/asn1"
	"regexp"
)

// The DER a token is held to (the Crypto API, Timestamps). Every element of a token, read or not, keeps
// DER's rules that need no schema: minimal definite lengths, strings in the primitive form, minimal
// integers and object identifiers, booleans, a BIT STRING's unused bits zero, UTCTime and
// GeneralizedTime in DER's one form, and each SET's elements in DER's order. A SET OF implicitly
// tagged, a SignedData's certificates and CRLs and a signer info's unsigned attributes, is in any
// order, since only the signed attributes' DER is signed, and a SET inside it keeps DER's order. In the
// parts a reader reads, its TSTInfo, its signed attributes, its signer info and each certificate it
// carries, a DEFAULT written out is refused too, of those Timestamps lists alone: a certificate's
// version v1, an extension's critical FALSE, basicConstraints' cA FALSE, a GeneralSubtree's minimum 0,
// a field of RSASSA-PSS-params at its DEFAULT where the parameters parse as that type, the trailing zero bits of every named bit list, keyUsage's and a
// distribution point's reasons among them, and an ESSCertIDv2's hash of id-sha256 with its parameters
// absent. An extension's value is one element with nothing after it, in the TSTInfo and in each
// certificate, and each extension RFC 5280 defines parses as its schema (schema.go).
//
// A token nests at most maxDepth deep: its ContentInfo is depth 1, each element inside another adds
// one, and so does an element inside an OCTET STRING that holds DER, the TSTInfo inside its eContent and
// an extension's value inside its extnValue, each walked at the depth it has in the token. DER inside a
// BIT STRING, a key's RSAPublicKey or a signature, is no element of the token, and is not walked: bits
// that are not DER make a key in another form, or a signature that does not verify.
//
// encoding/asn1 holds what it reads to DER's lengths, integers and booleans, and nothing it reads as a
// RawValue, so a walk of every element checks what it does not.

// maxDepth is the deepest an element of a token nests, as Timestamps counts depth.
const maxDepth = 64

// The depths, as Timestamps counts them, of the parts of a token walked on their own: the SET of a
// signer info's signed attributes, under [0] in the signer info; a certificate the SignedData carries,
// in its certificates' [0]; and the TSTInfo, inside its eContent's OCTET STRING. An extension's value
// is extensionValueBelow under its certificate or its TSTInfo.
const (
	depthSignedAttributes = 6
	depthCertificate      = 5
	depthTSTInfo          = 7
	// A certificate's extension's value: TBSCertificate, [3], Extensions, Extension, extnValue, then the
	// value. A TSTInfo's: [1], Extensions, Extension, extnValue, then the value.
	certificateExtensionValueBelow = 6
	infoExtensionValueBelow        = 4
)

// element is one TLV: its identifier byte's class, form and tag, and its contents.
type element struct {
	class       int
	constructed bool
	tag         int
	contents    []byte
	full        []byte
}

// readElement reads the element b begins with, in DER's form: a tag in its shortest form, a definite
// length in its shortest form, and contents within b.
func readElement(b []byte) (element, []byte, error) {
	if len(b) < 2 {
		return element{}, nil, errDER
	}
	e := element{class: int(b[0] >> 6), constructed: b[0]&0x20 != 0, tag: int(b[0] & 0x1f)}
	i := 1
	if e.tag == 0x1f {
		// The high tag form, for a tag of 31 or more alone, base 128 with no leading zero digit.
		e.tag = 0
		for {
			if i >= len(b) || i > 4 || (e.tag == 0 && b[i] == 0x80) {
				return element{}, nil, errDER
			}
			e.tag = e.tag<<7 | int(b[i]&0x7f)
			i++
			if b[i-1]&0x80 == 0 {
				break
			}
		}
		if e.tag < 0x1f {
			return element{}, nil, errDER
		}
	}
	if i >= len(b) {
		return element{}, nil, errDER
	}
	n := int(b[i])
	i++
	if n&0x80 != 0 {
		// The long form, of one to four bytes, with no leading zero, for a length of 128 or more alone.
		// 0x80 alone is BER's indefinite length, which DER has not.
		k := n & 0x7f
		if k == 0 || k > 4 || i+k > len(b) || b[i] == 0 {
			return element{}, nil, errDER
		}
		n = 0
		for _, c := range b[i : i+k] {
			n = n<<8 | int(c)
		}
		i += k
		if n < 0x80 {
			return element{}, nil, errDER
		}
	}
	if n > len(b)-i {
		return element{}, nil, errDER
	}
	e.contents, e.full = b[i:i+n:i+n], b[:i+n:i+n]
	return e, b[i+n:], nil
}

// Universal tags the walk checks.
const (
	tagBoolean         = 1
	tagInteger         = 2
	tagBitString       = 3
	tagOctetString     = 4
	tagNull            = 5
	tagOID             = 6
	tagEnumerated      = 10
	tagUTF8String      = 12
	tagRelativeOID     = 13
	tagSequence        = 16
	tagSet             = 17
	tagUTCTime         = 23
	tagGeneralizedTime = 24
)

// isString is whether tag is one of ASN.1's string types, which DER writes in the primitive form alone.
func isString(tag int) bool {
	switch tag {
	case tagBitString, tagOctetString, tagUTF8String, tagUTCTime, tagGeneralizedTime,
		18, 19, 20, 21, 22, 25, 26, 27, 28, 30:
		return true
	}
	return false
}

var (
	utcTimeForm         = regexp.MustCompile(`^[0-9]{12}Z$`)
	generalizedTimeForm = regexp.MustCompile(`^[0-9]{14}(\.[0-9]*[1-9])?Z$`)
)

// walk holds b, a run of elements each at depth, as Timestamps counts depth, to DER's lengths, string
// forms, integers and booleans, and where full is set, to all of DER that holds of any schema: a BIT
// STRING's unused bits zero, UTCTime and GeneralizedTime in their one form, and each SET's elements in
// DER's order. An element deeper than maxDepth is refused before it is read, so the walk's stack is
// bounded whatever the bytes.
func walk(b []byte, full bool, depth int) error {
	if len(b) > 0 && depth > maxDepth {
		return errDER
	}
	for len(b) > 0 {
		e, rest, err := readElement(b)
		if err != nil {
			return err
		}
		if err := checkElement(e, full, depth); err != nil {
			return err
		}
		b = rest
	}
	return nil
}

func checkElement(e element, full bool, depth int) error {
	if e.class != asn1.ClassUniversal {
		if e.constructed {
			return walk(e.contents, full, depth+1)
		}
		return nil
	}
	if isString(e.tag) && e.constructed {
		return errDER
	}
	c := e.contents
	switch e.tag {
	case 0:
		// End-of-contents, which only BER's indefinite lengths need.
		return errDER
	case tagBoolean:
		if e.constructed || len(c) != 1 || (c[0] != 0 && c[0] != 0xff) {
			return errDER
		}
	case tagInteger, tagEnumerated:
		if e.constructed || !minimalInteger(c) {
			return errDER
		}
	case tagNull:
		if e.constructed || len(c) != 0 {
			return errDER
		}
	case tagOID, tagRelativeOID:
		if e.constructed || !minimalSubidentifiers(c) {
			return errDER
		}
	case tagBitString:
		if len(c) == 0 || c[0] > 7 || (len(c) == 1 && c[0] != 0) {
			return errDER
		}
		if full && len(c) > 1 && c[len(c)-1]&(1<<c[0]-1) != 0 {
			return errDER
		}
	case tagUTCTime:
		if full && !utcTimeForm.Match(c) {
			return errDER
		}
	case tagGeneralizedTime:
		if full && !generalizedTimeForm.Match(c) {
			return errDER
		}
	case tagSequence, tagSet:
		if !e.constructed {
			return errDER
		}
		if e.tag == tagSet && full {
			if err := inOrder(e.contents); err != nil {
				return err
			}
		}
		return walk(e.contents, full, depth+1)
	default:
		if e.constructed {
			return walk(e.contents, full, depth+1)
		}
	}
	return nil
}

// minimalInteger is whether c is an INTEGER's contents in DER: at least one byte, and no leading byte
// that only repeats the sign of the next.
func minimalInteger(c []byte) bool {
	if len(c) == 0 {
		return false
	}
	return len(c) == 1 || (c[0] != 0 || c[1]&0x80 != 0) && (c[0] != 0xff || c[1]&0x80 == 0)
}

// minimalSubidentifiers is whether c is an OBJECT IDENTIFIER's contents in DER: at least one byte, each
// subidentifier in base 128 with no leading zero digit, and the last one ended.
func minimalSubidentifiers(c []byte) bool {
	if len(c) == 0 || c[len(c)-1]&0x80 != 0 {
		return false
	}
	start := true
	for _, d := range c {
		if start && d == 0x80 {
			return false
		}
		start = d&0x80 == 0
	}
	return true
}

// inOrder is nil where the elements b holds are in DER's order for a SET OF: ascending, compared as
// octet strings, the shorter padded with zero bytes at its end (X.690, 11.6). A SET of distinct types is
// ordered by its tags, which this order keeps for the tags a token's SETs hold.
func inOrder(b []byte) error {
	var prev []byte
	for len(b) > 0 {
		e, rest, err := readElement(b)
		if err != nil {
			return err
		}
		if prev != nil && compareDER(prev, e.full) > 0 {
			return errDER
		}
		prev, b = e.full, rest
	}
	return nil
}

func compareDER(a, b []byte) int {
	n := min(len(a), len(b))
	if c := bytes.Compare(a[:n], b[:n]); c != 0 {
		return c
	}
	pad := func(rest []byte) int {
		for _, x := range rest {
			if x != 0 {
				return 1
			}
		}
		return 0
	}
	switch {
	case len(a) > n:
		return pad(a[n:])
	case len(b) > n:
		return -pad(b[n:])
	}
	return 0
}

// elementsOf is the elements of the contents b, in DER's form.
func elementsOf(b []byte) ([]element, error) {
	var out []element
	for len(b) > 0 {
		e, rest, err := readElement(b)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
		b = rest
	}
	return out, nil
}

func (e element) is(class, tag int, constructed bool) bool {
	return e.class == class && e.tag == tag && e.constructed == constructed
}

// explicitFalse is whether e is a BOOLEAN written out as FALSE, which DER leaves out where FALSE is the
// DEFAULT: an extension's critical, and basicConstraints' cA.
func explicitFalse(e element) bool {
	return e.is(asn1.ClassUniversal, tagBoolean, false) && len(e.contents) == 1 && e.contents[0] == 0
}

// derSignerInfoAlgorithm holds a signer info, its DER whole, to RSASSA-PSS's DEFAULTs in its signature
// algorithm: the element after its digestAlgorithm, and after its signed attributes where it has them.
func derSignerInfoAlgorithm(der []byte) error {
	si, _, err := readElement(der)
	if err != nil {
		return errDER
	}
	parts, err := elementsOf(si.contents)
	if err != nil || len(parts) < 5 {
		return errDER
	}
	i := 3 // version, sid, digestAlgorithm, then the signature algorithm
	if parts[3].is(asn1.ClassContextSpecific, 0, true) {
		i++ // after [0] the signed attributes
	}
	return derAlgorithm(parts[i])
}

// derAlgorithm holds an AlgorithmIdentifier of a certificate or a signer info to RSASSA-PSS's
// DEFAULTs, where it is RSASSA-PSS's and its parameters parse as RSASSA-PSS-params: no SHA-1 hash or
// mask, salt of 20 bytes or trailer field of 1 written out (RFC 4055, 3.1). Parameters of any other
// form, no SEQUENCE, or a SEQUENCE that is no RSASSA-PSS-params, such as one with an INTEGER before a
// field at its DEFAULT, write out no DEFAULT of that type: they verify nothing, and fail no parse, as the
// Crypto API's Timestamps sets.
func derAlgorithm(a element) error {
	parts, err := elementsOf(a.contents)
	if err != nil || len(parts) == 0 {
		return errDER
	}
	id, ok := oidOf(parts[0])
	if !ok {
		return errDER
	}
	if id != oidRSASSAPSS || len(parts) < 2 {
		return nil
	}
	params, ok := rsassaPSSParams(parts[1])
	if !ok {
		return nil
	}
	for _, p := range params {
		var def []byte
		switch p.tag {
		case 0:
			def = pssSHA1
		case 1:
			def = pssMGF1SHA1
		case 2:
			def = []byte{0x02, 0x01, 20}
		case 3:
			def = []byte{0x02, 0x01, 1}
		}
		if def != nil && bytes.Equal(p.contents, def) {
			return errDER
		}
	}
	return nil
}

// rsassaPSSParams is the fields of e where e parses as RSASSA-PSS-params, as RFC 4055's ASN.1 module of
// 1988 writes it: a SEQUENCE of hashAlgorithm [0], maskGenAlgorithm [1], saltLength [2] and trailerField
// [3], each explicitly tagged, optional, at most once and in that order, the first two an
// AlgorithmIdentifier and the last two an INTEGER, and nothing else. ok is false for parameters of any
// other form.
func rsassaPSSParams(e element) (fields []element, ok bool) {
	if !e.is(asn1.ClassUniversal, tagSequence, true) {
		return nil, false
	}
	fields, err := elementsOf(e.contents)
	if err != nil {
		return nil, false
	}
	last := -1
	for _, f := range fields {
		if f.class != asn1.ClassContextSpecific || !f.constructed || f.tag <= last || f.tag > 3 {
			return nil, false
		}
		last = f.tag
		inner, err := elementsOf(f.contents)
		if err != nil || len(inner) != 1 {
			return nil, false
		}
		if f.tag <= 1 && !algorithmIdentifier5280(inner[0]) || f.tag >= 2 && !isInteger(inner[0]) {
			return nil, false
		}
	}
	return fields, true
}

// RSASSA-PSS-params' DEFAULT hash, SHA-1 with NULL parameters, and its DEFAULT mask, MGF1 under it, as
// DER writes each.
var (
	pssSHA1     = sequenceDER(mustMarshal(oidSHA1), asn1.NullBytes)
	pssMGF1SHA1 = sequenceDER(mustMarshal(OIDMGF1), pssSHA1)
)

// sequenceDER is the DER of a SEQUENCE of parts, each already DER.
func sequenceDER(parts ...[]byte) []byte {
	return mustMarshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: bytes.Join(parts, nil)})
}

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic("timestamp: " + err.Error())
	}
	return b
}

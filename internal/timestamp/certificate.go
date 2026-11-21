package timestamp

import (
	"bytes"
	"cmp"
	"encoding/asn1"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// A certificate a token carries, and a root, as Timestamps sets: every element in DER's rules that need
// no schema, nested as deep as a carried certificate may; X.509's ASN.1 alone outside its extensions,
// each field of its TBSCertificate and its signatureAlgorithm as that ASN.1 sets it; each extension RFC
// 5280 defines as RFC 5280's ASN.1 modules set its schema (schema.go); and no DEFAULT written out of
// those Timestamps lists. RFC 5280's text binds the CA that writes a certificate, not a reader, but for
// two rules, each giving two readings of what the chain reads: an extension given twice, and a
// signature other than its signatureAlgorithm, which each make a certificate not parse.
//
// So a version above v3, a serial that is not positive, a unique identifier or extensions in a
// certificate of a version RFC 5280 does not give them, a name's characters outside its string type, a
// path length of any size, and a validity time with a fraction of a second each parse. crypto/x509
// refuses some of them, so no certificate is read through it: this file reads each part the chain
// reads, and the chain verifies under crypto/x509's CheckSignature alone.

// OID is an object identifier as DER writes its contents, compared byte for byte. The walk holds every
// identifier to DER, so one identifier has one OID, and one of any size reads, an arc past 2^31 among
// them, which encoding/asn1 does not read.
type OID string

// NewOID is id's OID.
func NewOID(id asn1.ObjectIdentifier) OID {
	e, _, err := readElement(mustMarshal(id))
	if err != nil {
		panic("timestamp: an object identifier encoding/asn1 writes that does not read")
	}
	return OID(e.contents)
}

// oidOf is the OID e is, where e is an OBJECT IDENTIFIER.
func oidOf(e element) (OID, bool) {
	if !isOID(e) {
		return "", false
	}
	return OID(e.contents), true
}

// Instant is a time as a certificate's validity or a genTime writes it, exactly: its whole seconds
// since 1970 in UTC, and the digits of its fraction of a second as written, with no trailing zero and
// empty where it has none. A fraction is kept whole, however fine, so two instants compare exactly.
type Instant struct {
	Seconds  int64
	Fraction string
}

// Compare is -1 where i is before o, 0 where they are one instant, and +1 where i is after o.
func (i Instant) Compare(o Instant) int {
	if c := cmp.Compare(i.Seconds, o.Seconds); c != 0 {
		return c
	}
	// Digits of a fraction compare as text once both are as long, the shorter padded with zeros.
	n := max(len(i.Fraction), len(o.Fraction))
	return strings.Compare(i.Fraction+strings.Repeat("0", n-len(i.Fraction)), o.Fraction+strings.Repeat("0", n-len(o.Fraction)))
}

// Floor is the whole second at or before i, in UTC.
func (i Instant) Floor() time.Time { return time.Unix(i.Seconds, 0).UTC() }

// Ceil is the whole second at or after i, in UTC: i rounded up where it has a fraction.
func (i Instant) Ceil() time.Time {
	if i.Fraction != "" {
		return time.Unix(i.Seconds+1, 0).UTC()
	}
	return i.Floor()
}

var (
	utcTimeDigits         = regexp.MustCompile(`^([0-9]{2})([0-9]{10})Z$`)
	generalizedTimeDigits = regexp.MustCompile(`^([0-9]{14})(?:\.([0-9]*[1-9]))?Z$`)
)

// instantOf is the instant a UTCTime or a GeneralizedTime in DER's form writes, and false where it
// writes no time: a month, a day, an hour, a minute or a second outside its range, a second of 60
// among them, since time.Parse refuses each. A UTCTime's year below 50 is in the 2000s, and from 50 in
// the 1900s (RFC 5280, 4.1.2.5.1).
func instantOf(e element) (Instant, bool) {
	var digits, fraction string
	switch {
	case e.is(asn1.ClassUniversal, tagUTCTime, false):
		m := utcTimeDigits.FindSubmatch(e.contents)
		if m == nil {
			return Instant{}, false
		}
		century := "20"
		if yy, _ := strconv.Atoi(string(m[1])); yy >= 50 {
			century = "19"
		}
		digits = century + string(m[1]) + string(m[2])
	case e.is(asn1.ClassUniversal, tagGeneralizedTime, false):
		m := generalizedTimeDigits.FindSubmatch(e.contents)
		if m == nil {
			return Instant{}, false
		}
		digits, fraction = string(m[1]), string(m[2])
	default:
		return Instant{}, false
	}
	t, err := time.ParseInLocation("20060102150405", digits, time.UTC)
	if err != nil {
		return Instant{}, false
	}
	return Instant{Seconds: t.Unix(), Fraction: fraction}, true
}

// Certificate is a certificate a token carries, or a root, as the chain reads it.
type Certificate struct {
	// Raw is the certificate's DER, and TBS its TBSCertificate's, which its issuer signs.
	Raw, TBS []byte
	// Serial is its serialNumber, of any sign.
	Serial *big.Int
	// Issuer and Subject are the DER of each Name, which the chain compares byte for byte.
	Issuer, Subject []byte
	// NotBefore and NotAfter are its validity, each exactly as written.
	NotBefore, NotAfter Instant
	// SubjectPublicKeyInfo is the DER of its key, an AlgorithmIdentifier and a BIT STRING, in whatever
	// form: which form verifies is the chain's to tell.
	SubjectPublicKeyInfo []byte
	// SignatureAlgorithm is the DER of its signatureAlgorithm, which its TBSCertificate's signature is
	// byte for byte, and Signature its signature's bytes, nil where its BIT STRING has unused bits and so
	// holds no whole bytes: a signature that verifies nothing.
	SignatureAlgorithm []byte
	Signature          []byte
	// Extensions are each of its extensions, in its order.
	Extensions []Extension
}

// Extension is a certificate's extension: its id, whether it is critical, and its value, the DER of one
// element.
type Extension struct {
	ID       OID
	Critical bool
	Value    []byte
}

// ParseCertificate reads der as a certificate a token carries, or a root, held to what Timestamps sets
// of one, nested as deep as a carried certificate may: a root is held to it before a token is checked
// under it. Every error is ErrMalformed, and quotes nothing of der.
func ParseCertificate(der []byte) (*Certificate, error) {
	c, err := parseCertificate(der, depthCertificate)
	if err != nil {
		return nil, ErrMalformed
	}
	return c, nil
}

// The object identifiers whose DEFAULTs or schemas a certificate's DER is checked for.
var (
	oidBasicConstraints = NewOID(asn1.ObjectIdentifier{2, 5, 29, 19})
	oidKeyUsage         = NewOID(asn1.ObjectIdentifier{2, 5, 29, 15})
	oidExtKeyUsage      = NewOID(asn1.ObjectIdentifier{2, 5, 29, 37})
	oidSubjectKeyID     = NewOID(asn1.ObjectIdentifier{2, 5, 29, 14})
	oidRSASSAPSS        = NewOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10})
)

// parseCertificate reads der, at depth, as X.509's ASN.1 sets a certificate:
//
//	Certificate ::= SEQUENCE { tbsCertificate TBSCertificate, signatureAlgorithm AlgorithmIdentifier,
//	  signature BIT STRING }
//	TBSCertificate ::= SEQUENCE { version [0] EXPLICIT Version DEFAULT v1, serialNumber INTEGER,
//	  signature AlgorithmIdentifier, issuer Name, validity Validity, subject Name,
//	  subjectPublicKeyInfo SubjectPublicKeyInfo, issuerUniqueID [1] IMPLICIT BIT STRING OPTIONAL,
//	  subjectUniqueID [2] IMPLICIT BIT STRING OPTIONAL, extensions [3] EXPLICIT Extensions OPTIONAL }
//	Validity ::= SEQUENCE { notBefore Time, notAfter Time }
//	SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
//
// each AlgorithmIdentifier an object identifier and at most its parameters, of any value, a Version of
// any value but v1 written out, and nothing after a part's fields.
func parseCertificate(der []byte, depth int) (*Certificate, error) {
	if err := walk(der, true, depth); err != nil {
		return nil, err
	}
	cert, rest, err := readElement(der)
	if err != nil || len(rest) > 0 || !cert.is(asn1.ClassUniversal, tagSequence, true) {
		return nil, errDER
	}
	outer, err := elementsOf(cert.contents)
	if err != nil || len(outer) != 3 || !outer[0].is(asn1.ClassUniversal, tagSequence, true) ||
		!algorithmIdentifier5280(outer[1]) || !outer[2].is(asn1.ClassUniversal, tagBitString, false) {
		return nil, errDER
	}
	c := &Certificate{Raw: cert.full, TBS: outer[0].full, SignatureAlgorithm: outer[1].full}
	// The walk holds the BIT STRING to DER: its unused bits at most 7, and zero.
	if bits := outer[2].contents; bits[0] == 0 {
		c.Signature = bytes.Clone(bits[1:])
	}

	tbs, err := elementsOf(outer[0].contents)
	if err != nil {
		return nil, errDER
	}
	if len(tbs) > 0 && tbs[0].is(asn1.ClassContextSpecific, 0, true) {
		// [0] EXPLICIT Version DEFAULT v1: one INTEGER, its DEFAULT, v1, never written out.
		v, ok := children(tbs[0])
		if !ok || len(v) != 1 || !isInteger(v[0]) || bytes.Equal(v[0].contents, []byte{0}) {
			return nil, errDER
		}
		tbs = tbs[1:]
	}
	if len(tbs) < 6 || !isInteger(tbs[0]) || !bytes.Equal(tbs[1].full, outer[1].full) ||
		!distinguishedName(tbs[2]) || !distinguishedName(tbs[4]) {
		return nil, errDER
	}
	if _, err := asn1.Unmarshal(tbs[0].full, &c.Serial); err != nil {
		return nil, errDER
	}
	c.Issuer, c.Subject = tbs[2].full, tbs[4].full
	validity, ok := children(tbs[3])
	if !ok || !tbs[3].is(asn1.ClassUniversal, tagSequence, true) || len(validity) != 2 {
		return nil, errDER
	}
	if c.NotBefore, ok = instantOf(validity[0]); !ok {
		return nil, errDER
	}
	if c.NotAfter, ok = instantOf(validity[1]); !ok {
		return nil, errDER
	}
	spki, ok := children(tbs[5])
	if !ok || !tbs[5].is(asn1.ClassUniversal, tagSequence, true) || len(spki) != 2 || !algorithmIdentifier5280(spki[0]) ||
		!spki[1].is(asn1.ClassUniversal, tagBitString, false) {
		return nil, errDER
	}
	c.SubjectPublicKeyInfo = tbs[5].full
	// RSASSA-PSS's DEFAULTs written out are refused wherever an AlgorithmIdentifier names it: the
	// signatureAlgorithm, which the TBSCertificate's signature is, and the key's, whose key verifies
	// nothing but is the certificate's DER all the same.
	if derAlgorithm(outer[1]) != nil || derAlgorithm(spki[0]) != nil {
		return nil, errDER
	}

	// After the key, only issuerUniqueID [1], subjectUniqueID [2] and extensions [3], in that order,
	// each at most once, so a certificate gives its extensions once, in one [3].
	last := 0
	for _, p := range tbs[6:] {
		if p.class != asn1.ClassContextSpecific || p.tag <= last || p.tag > 3 {
			return nil, errDER
		}
		last = p.tag
		if p.tag < 3 {
			// UniqueIdentifier ::= BIT STRING, implicitly tagged.
			if !implicitBitString(p) {
				return nil, errDER
			}
			continue
		}
		if !p.constructed {
			return nil, errDER
		}
		if c.Extensions, err = parseExtensions(p.contents, depth+certificateExtensionValueBelow); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// algorithmIdentifier5280 is whether e is an AlgorithmIdentifier: SEQUENCE { algorithm OBJECT
// IDENTIFIER, parameters ANY DEFINED BY algorithm OPTIONAL }, an object identifier and at most its
// parameters, one element under the rules that need no schema alone.
func algorithmIdentifier5280(e element) bool {
	parts, ok := children(e)
	return ok && e.is(asn1.ClassUniversal, tagSequence, true) && len(parts) >= 1 && len(parts) <= 2 && isOID(parts[0])
}

// parseExtensions reads [3]'s contents, one element: Extensions ::= SEQUENCE SIZE (1..MAX) OF
// Extension, each in its one shape, none given twice, and each value, at depth, DER of one element that
// parses as its schema where RFC 5280 defines its extension.
func parseExtensions(b []byte, depth int) ([]Extension, error) {
	seq, rest, err := readElement(b)
	if err != nil || len(rest) > 0 || !seq.is(asn1.ClassUniversal, tagSequence, true) {
		return nil, errDER
	}
	exts, err := elementsOf(seq.contents)
	if err != nil || len(exts) == 0 {
		return nil, errDER
	}
	out := make([]Extension, 0, len(exts))
	for _, x := range exts {
		parts, err := elementsOf(x.contents)
		if err != nil || !x.is(asn1.ClassUniversal, tagSequence, true) || !extensionShaped(parts) {
			return nil, errDER
		}
		id, _ := oidOf(parts[0])
		// A certificate gives no extension twice (RFC 5280, 4.2): it would give two readings of what the
		// chain reads.
		for _, seen := range out {
			if seen.ID == id {
				return nil, errDER
			}
		}
		value := parts[len(parts)-1].contents
		if err := walk(value, true, depth); err != nil {
			return nil, err
		}
		v, rest, err := readElement(value)
		if err != nil || len(rest) > 0 || !rfc5280Schema(id, v) {
			return nil, errDER
		}
		out = append(out, Extension{ID: id, Critical: len(parts) == 3, Value: value})
	}
	return out, nil
}

// Extension is c's extension of id, and false where it has none.
func (c *Certificate) Extension(id OID) (Extension, bool) {
	for _, e := range c.Extensions {
		if e.ID == id {
			return e, true
		}
	}
	return Extension{}, false
}

// BasicConstraints is c's basicConstraints, which parses as its schema: whether c has one, its cA, and
// its pathLenConstraint, -1 where it gives none, and math.MaxInt where it is more than an int holds,
// which no chain of eight certificates reaches.
func (c *Certificate) BasicConstraints() (present, ca bool, pathLen int) {
	e, ok := c.Extension(oidBasicConstraints)
	if !ok {
		return false, false, -1
	}
	v, _, _ := readElement(e.Value)
	parts, _ := elementsOf(v.contents)
	pathLen = -1
	for _, p := range parts {
		switch {
		case p.is(asn1.ClassUniversal, tagBoolean, false):
			ca = p.contents[0] != 0
		case isInteger(p):
			n := new(big.Int).SetBytes(p.contents) // 0 or more, as its schema holds
			pathLen = math.MaxInt
			if n.IsInt64() && n.Int64() < math.MaxInt32 {
				pathLen = int(n.Int64())
			}
		}
	}
	return true, ca, pathLen
}

// KeyUsage is c's keyUsage's bits, the BIT STRING's bytes after its count of unused bits, and whether c
// has a keyUsage. A keyUsage of no bit set is one all the same, which signs nothing.
func (c *Certificate) KeyUsage() (bits []byte, present bool) {
	e, ok := c.Extension(oidKeyUsage)
	if !ok {
		return nil, false
	}
	v, _, _ := readElement(e.Value)
	return v.contents[1:], true
}

// ExtKeyUsage is each key purpose c's extendedKeyUsage names, none where it has none.
func (c *Certificate) ExtKeyUsage() []OID {
	e, ok := c.Extension(oidExtKeyUsage)
	if !ok {
		return nil
	}
	v, _, _ := readElement(e.Value)
	parts, _ := elementsOf(v.contents)
	out := make([]OID, 0, len(parts))
	for _, p := range parts {
		id, _ := oidOf(p)
		out = append(out, id)
	}
	return out
}

// SubjectKeyID is c's subject key identifier, nil where it has none.
func (c *Certificate) SubjectKeyID() []byte {
	e, ok := c.Extension(oidSubjectKeyID)
	if !ok {
		return nil
	}
	v, _, _ := readElement(e.Value)
	return v.contents
}

// extensionShaped is whether parts, an Extension's elements, are its one shape in DER: extnID, then
// extnValue, an OCTET STRING, with critical between them where it is TRUE, its DEFAULT FALSE left out.
// No element is read as the value but the last of that shape, so no reader can take another.
func extensionShaped(parts []element) bool {
	switch {
	case len(parts) == 2:
	case len(parts) == 3 && parts[1].is(asn1.ClassUniversal, tagBoolean, false) && len(parts[1].contents) == 1 && parts[1].contents[0] == 0xff:
	default:
		return false
	}
	return isOID(parts[0]) && parts[len(parts)-1].is(asn1.ClassUniversal, tagOctetString, false)
}

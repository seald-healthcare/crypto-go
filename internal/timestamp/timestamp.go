// Package timestamp reads an RFC 3161 TimeStampToken, a CMS SignedData (RFC 5652), for verify's
// VerifyTimestamp, as the contract's Timestamps names its parts (the Crypto API, Timestamps). It reads,
// and checks nothing but the DER and the ASN.1: which parts a token must hold, and what each must be,
// is verify's.
//
// It holds every element of the token, read or not, to DER's rules that need no schema, nested at most
// 64 deep, and refuses in its TSTInfo, its signed attributes, its signer info and each certificate the
// DEFAULTs written out that Timestamps lists, as Timestamps sets (der.go). It reads each certificate
// the token carries, and each root, as X.509's ASN.1 sets it alone outside its extensions
// (certificate.go). It holds each extension's value to one element, each extension RFC 5280 defines in
// a certificate to RFC 5280's ASN.1 modules, and each required signed attribute to RFC 5652's and RFC
// 5035's, read as an extension's schema is (schema.go). It reads an RFC 4998 evidence record too, as
// the contract's Renewal does, for verify to check (evidence.go). It reads only the parts Timestamps
// names, the CMS over encoding/asn1, and each part it reads holds its elements and nothing after them,
// where encoding/asn1 would skip what follows the last: a token whose bytes are BER, or that holds a
// part Timestamps names in another form, does not parse. What it does not read, such as a CRL or an
// unsigned attribute, it holds to DER's rules that need no schema, and skips. An object identifier is
// read whatever its size, an arc past 2^31 among them, which encoding/asn1 does not read. The standard
// library has no CMS parser, and a module that has one parses all of CMS, far more than a token holds.
//
// Every error is the token's, never the caller's, and quotes nothing of it. Parse never panics on any
// bytes, which FuzzParse holds it to.
package timestamp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
)

// The object identifiers Timestamps names.
var (
	OIDSignedData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDTSTInfo              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	OIDContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDMessageDigest        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	OIDSHA256               = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

// Token is what a TimeStampToken holds, of the parts Timestamps names.
type Token struct {
	// Version is the SignedData's.
	Version int
	// Certificates are each X.509 certificate the SignedData carries, in its order, and
	// CertificateChoices how many certificates it carries of any form, which Certificates leaves out
	// but for X.509's.
	Certificates       []*Certificate
	CertificateChoices int
	// SignerInfos are each signer info, in its order.
	SignerInfos []SignerInfo
	// EContentType is the encapsulated content's type, nil for an identifier of an arc past 2^31 that
	// names nothing Timestamps names, and EContent its bytes, the DER of Info, which a messageDigest
	// attribute is the digest of.
	EContentType asn1.ObjectIdentifier
	EContent     []byte
	// Info is EContent read as a TSTInfo.
	Info Info
}

// SignerInfo is a signer info. Its signer is named by Issuer and Serial, or by SubjectKeyID, never by
// both.
type SignerInfo struct {
	// Version is the signer info's.
	Version int
	// Issuer is the DER of the issuer's Name, and Serial the certificate's serial number, where the
	// signer info names its signer by issuer and serial number.
	Issuer []byte
	Serial *big.Int
	// SubjectKeyID is the signer's subject key identifier, where it names its signer by it.
	SubjectKeyID []byte
	// DigestAlgorithm is the hash of messageDigest and of the signed attributes.
	DigestAlgorithm pkix.AlgorithmIdentifier
	// SignedAttributes is the DER of the signed attributes as a SET OF, what the signature is over
	// (RFC 5652, 5.4), and nil where the signer info has none.
	SignedAttributes []byte
	// ContentType, MessageDigest and SigningCertificateV2 are the values of each of those signed
	// attributes, one for each value of each attribute of the type, so an attribute given twice, or
	// with two values, gives two. Any other attribute is skipped.
	ContentType          []asn1.ObjectIdentifier
	MessageDigest        [][]byte
	SigningCertificateV2 []SigningCertificateV2
	// SignatureAlgorithm and Signature are the signature over SignedAttributes.
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

// SigningCertificateV2 is RFC 5035's SigningCertificateV2. Its policies are skipped.
type SigningCertificateV2 struct {
	Certs []ESSCertIDv2
}

// ESSCertIDv2 binds a certificate by its hash.
type ESSCertIDv2 struct {
	// HashAlgorithm is the hash of CertHash, SHA-256 where the ESSCertIDv2 leaves it out, as its
	// default.
	HashAlgorithm pkix.AlgorithmIdentifier
	CertHash      []byte
	// IssuerSerial is the certificate's issuer and serial number, and nil where it is left out.
	IssuerSerial *IssuerSerial
}

// IssuerSerial is RFC 5035's IssuerSerial.
type IssuerSerial struct {
	// DirectoryNames is the DER of each directoryName among its GeneralNames, and Names how many
	// GeneralNames it holds of any choice.
	DirectoryNames [][]byte
	Names          int
	Serial         *big.Int
}

// Info is what a TSTInfo holds, of the parts Timestamps names. Its policy, serial number, accuracy,
// ordering, nonce and tsa are read, as DER, and not kept. ordering may be written out as FALSE, its
// DEFAULT, which Timestamps does not list among the DEFAULTs it refuses.
type Info struct {
	Version       int
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
	// GenTime is the token's time exactly, the fraction of a second it gives kept whole, however fine.
	GenTime    Instant
	Extensions []pkix.Extension
}

// ErrMalformed is the error of every token Parse cannot read. It never says where, so it quotes
// nothing of the token.
var ErrMalformed = errors.New("timestamp: a token that does not parse")

// Parse reads der as a TimeStampToken: a ContentInfo of signed data, whose encapsulated content is
// read as a TSTInfo whatever its type says, and nothing after it.
func Parse(der []byte) (*Token, error) {
	t, err := parse(der)
	if err != nil {
		return nil, ErrMalformed
	}
	return t, nil
}

// The ASN.1 of a token, as encoding/asn1 reads it. A part in a context tag is read as a RawValue in
// that tag and then read inside, whether its tag is explicit or implicit, so no part hangs on how
// encoding/asn1 reads an explicit RawValue. encoding/asn1 skips what a SEQUENCE holds after the
// fields of its struct, so each struct ends in After, which takes the first element left, and a part
// whose After holds one does not parse.

// after is the last field of every struct.
type after = asn1.RawValue

// An OBJECT IDENTIFIER is read as a RawValue, and then by identifier, since encoding/asn1 reads no
// identifier of an arc past 2^31, which DER keeps all the same.
type algorithmIdentifier struct {
	Algorithm  asn1.RawValue
	Parameters asn1.RawValue `asn1:"optional"`
	After      after         `asn1:"optional"`
}

// done is whether a is an object identifier and at most its parameters.
func (a algorithmIdentifier) done() bool {
	_, ok := identifier(a.Algorithm)
	return ok && len(a.After.FullBytes) == 0
}

func (a algorithmIdentifier) pkix() pkix.AlgorithmIdentifier {
	id, _ := identifier(a.Algorithm)
	return pkix.AlgorithmIdentifier{Algorithm: id, Parameters: a.Parameters}
}

// identifier is the object identifier v is, and false where v is no OBJECT IDENTIFIER. One of an arc
// past 2^31 − 1, which encoding/asn1 does not read, is nil: an identifier that names nothing Timestamps
// names, read all the same, since the walk has held it to DER.
func identifier(v asn1.RawValue) (asn1.ObjectIdentifier, bool) {
	if v.Class != asn1.ClassUniversal || v.Tag != asn1.TagOID || v.IsCompound {
		return nil, false
	}
	var id asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(v.FullBytes, &id); err != nil {
		return nil, true
	}
	return id, true
}

type extension struct {
	ID       asn1.RawValue
	Critical bool `asn1:"optional"`
	Value    []byte
	After    after `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.RawValue
	Content     asn1.RawValue `asn1:"tag:0"`
	After       after         `asn1:"optional"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo encapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
	After            after `asn1:"optional"`
}

type encapsulatedContentInfo struct {
	EContentType asn1.RawValue
	EContent     asn1.RawValue `asn1:"optional,tag:0"`
	After        after         `asn1:"optional"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    algorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
	After              after         `asn1:"optional"`
}

type issuerAndSerialNumber struct {
	Issuer asn1.RawValue
	Serial *big.Int
	After  after `asn1:"optional"`
}

type attribute struct {
	Type   asn1.RawValue
	Values asn1.RawValue
	After  after `asn1:"optional"`
}

type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
	After         after `asn1:"optional"`
}

var errDER = errors.New("not DER")

func parse(der []byte) (*Token, error) {
	if err := walk(der, true, 1); err != nil {
		return nil, err
	}
	var ci contentInfo
	if err := whole(der, &ci); err != nil {
		return nil, err
	}
	if id, _ := identifier(ci.ContentType); !id.Equal(OIDSignedData) || !ci.Content.IsCompound || len(ci.After.FullBytes) > 0 {
		return nil, errDER
	}
	var sd signedData
	if err := whole(ci.Content.Bytes, &sd); err != nil {
		return nil, err
	}
	if !isSet(sd.DigestAlgorithms) || !isSet(sd.SignerInfos) || len(sd.After.FullBytes) > 0 || len(sd.EncapContentInfo.After.FullBytes) > 0 {
		return nil, errDER
	}
	eContentType, ok := identifier(sd.EncapContentInfo.EContentType)
	if !ok {
		return nil, errDER
	}
	t := &Token{Version: sd.Version, EContentType: eContentType}

	e := sd.EncapContentInfo.EContent
	if !e.IsCompound {
		return nil, errDER
	}
	var content []byte
	if err := whole(e.Bytes, &content); err != nil {
		return nil, err
	}
	t.EContent = content
	if err := walk(content, true, depthTSTInfo); err != nil {
		return nil, err
	}
	info, err := parseInfo(content)
	if err != nil {
		return nil, err
	}
	t.Info = info

	if len(sd.Certificates.FullBytes) > 0 {
		if !sd.Certificates.IsCompound {
			return nil, errDER
		}
		err := each(sd.Certificates.Bytes, func(v asn1.RawValue) error {
			t.CertificateChoices++
			switch certificateForm(v) {
			case x509Form:
				c, err := parseCertificate(v.FullBytes, depthCertificate)
				if err != nil {
					return err
				}
				t.Certificates = append(t.Certificates, c)
			case otherForm:
			default:
				return errDER
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	err = each(sd.SignerInfos.Bytes, func(v asn1.RawValue) error {
		s, err := parseSignerInfo(v.FullBytes)
		if err != nil {
			return err
		}
		t.SignerInfos = append(t.SignerInfos, s)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return t, nil
}

// The forms of RFC 5652's CertificateChoices, which an element of a SignedData's certificates is of by
// its tag alone: certificate, a SEQUENCE, X.509's, and extendedCertificate, v1AttrCert, v2AttrCert and
// other, [0] to [3] IMPLICIT, each a SEQUENCE and so constructed.
const (
	noForm = iota
	x509Form
	otherForm
)

// certificateForm is the form of CertificateChoices v is of, by its tag alone, and noForm where it is
// of none: bytes that do not parse.
func certificateForm(v asn1.RawValue) int {
	switch {
	case !v.IsCompound:
		return noForm
	case v.Class == asn1.ClassUniversal && v.Tag == asn1.TagSequence:
		return x509Form
	case v.Class == asn1.ClassContextSpecific && v.Tag <= 3:
		return otherForm
	}
	return noForm
}

func parseSignerInfo(der []byte) (SignerInfo, error) {
	var si signerInfo
	if err := whole(der, &si); err != nil {
		return SignerInfo{}, err
	}
	if len(si.After.FullBytes) > 0 || !si.DigestAlgorithm.done() || !si.SignatureAlgorithm.done() {
		return SignerInfo{}, errDER
	}
	// The signer info is a part a reader reads, so RSASSA-PSS's DEFAULTs written out in its signature
	// algorithm are refused, as in a certificate's.
	if err := derSignerInfoAlgorithm(der); err != nil {
		return SignerInfo{}, err
	}
	s := SignerInfo{
		Version:            si.Version,
		DigestAlgorithm:    si.DigestAlgorithm.pkix(),
		SignatureAlgorithm: si.SignatureAlgorithm.pkix(),
		Signature:          si.Signature,
	}
	switch {
	case si.SID.Class == asn1.ClassUniversal && si.SID.Tag == asn1.TagSequence:
		var ias issuerAndSerialNumber
		if err := whole(si.SID.FullBytes, &ias); err != nil {
			return SignerInfo{}, err
		}
		if !isSequence(ias.Issuer) || len(ias.After.FullBytes) > 0 {
			return SignerInfo{}, errDER
		}
		s.Issuer, s.Serial = ias.Issuer.FullBytes, ias.Serial
	case si.SID.Class == asn1.ClassContextSpecific && si.SID.Tag == 0 && !si.SID.IsCompound:
		s.SubjectKeyID = si.SID.Bytes
	default:
		return SignerInfo{}, errDER
	}

	if len(si.SignedAttrs.FullBytes) == 0 {
		return s, nil
	}
	if !si.SignedAttrs.IsCompound {
		return SignerInfo{}, errDER
	}
	// The signature is over the attributes' DER under SET OF's own tag, where the signer info carries
	// them under [0]. A tag below 31 is one byte, so the tag is that byte alone.
	s.SignedAttributes = append([]byte{0x31}, si.SignedAttrs.FullBytes[1:]...)
	if err := walk(s.SignedAttributes, true, depthSignedAttributes); err != nil {
		return SignerInfo{}, err
	}
	err := each(si.SignedAttrs.Bytes, func(v asn1.RawValue) error {
		var a attribute
		if err := whole(v.FullBytes, &a); err != nil {
			return err
		}
		id, ok := identifier(a.Type)
		if !ok || !isSet(a.Values) || len(a.After.FullBytes) > 0 {
			return errDER
		}
		switch {
		case id.Equal(OIDContentType):
			return each(a.Values.Bytes, func(v asn1.RawValue) error {
				oid, ok := identifier(v)
				if !ok {
					return errDER
				}
				s.ContentType = append(s.ContentType, oid)
				return nil
			})
		case id.Equal(OIDMessageDigest):
			return each(a.Values.Bytes, func(v asn1.RawValue) error {
				var d []byte
				if err := whole(v.FullBytes, &d); err != nil {
					return err
				}
				s.MessageDigest = append(s.MessageDigest, d)
				return nil
			})
		case id.Equal(OIDSigningCertificateV2):
			return each(a.Values.Bytes, func(v asn1.RawValue) error {
				sc, err := parseSigningCertificateV2(v.FullBytes)
				if err != nil {
					return err
				}
				s.SigningCertificateV2 = append(s.SigningCertificateV2, sc)
				return nil
			})
		}
		return nil
	})
	if err != nil {
		return SignerInfo{}, err
	}
	return s, nil
}

// parseSigningCertificateV2 reads SEQUENCE { certs SEQUENCE OF ESSCertIDv2, policies SEQUENCE OF
// PolicyInformation OPTIONAL }, each ESSCertIDv2 and each PolicyInformation as RFC 5035 and RFC 5280
// set their schemas, with nothing after them.
func parseSigningCertificateV2(der []byte) (SigningCertificateV2, error) {
	body, err := sequence(der)
	if err != nil {
		return SigningCertificateV2{}, err
	}
	certs, rest, err := next(body)
	if err != nil || !isSequence(certs) {
		return SigningCertificateV2{}, errDER
	}
	if len(rest) > 0 {
		policies, rest, err := readElement(rest)
		if err != nil || len(rest) > 0 || !sequenceOf(policies, 0, policyInformation) {
			return SigningCertificateV2{}, errDER
		}
	}
	var sc SigningCertificateV2
	err = each(certs.Bytes, func(v asn1.RawValue) error {
		id, err := parseESSCertIDv2(v.FullBytes)
		if err != nil {
			return err
		}
		sc.Certs = append(sc.Certs, id)
		return nil
	})
	if err != nil {
		return SigningCertificateV2{}, err
	}
	return sc, nil
}

// parseESSCertIDv2 reads SEQUENCE { hashAlgorithm DEFAULT sha256, certHash OCTET STRING, issuerSerial
// OPTIONAL }.
func parseESSCertIDv2(der []byte) (ESSCertIDv2, error) {
	rest, err := sequence(der)
	if err != nil {
		return ESSCertIDv2{}, err
	}
	id := ESSCertIDv2{HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: OIDSHA256}}
	if tag, ok := peek(rest); ok && tag == idSequence {
		var a algorithmIdentifier
		if rest, err = asn1.Unmarshal(rest, &a); err != nil {
			return ESSCertIDv2{}, err
		}
		// DER leaves out hashAlgorithm where it is its DEFAULT, {algorithm id-sha256}.
		if !a.done() || a.pkix().Algorithm.Equal(OIDSHA256) && len(a.Parameters.FullBytes) == 0 {
			return ESSCertIDv2{}, errDER
		}
		id.HashAlgorithm = a.pkix()
	}
	if rest, err = asn1.Unmarshal(rest, &id.CertHash); err != nil {
		return ESSCertIDv2{}, err
	}
	if len(rest) == 0 {
		return id, nil
	}
	body, err := sequence(rest)
	if err != nil {
		return ESSCertIDv2{}, err
	}
	// IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber CertificateSerialNumber }, its
	// GeneralNames RFC 5280's.
	names, body, err := next(body)
	if err != nil || !isSequence(names) {
		return ESSCertIDv2{}, errDER
	}
	if e, _, err := readElement(names.FullBytes); err != nil || !generalNames(e) {
		return ESSCertIDv2{}, errDER
	}
	is := &IssuerSerial{}
	err = each(names.Bytes, func(v asn1.RawValue) error {
		is.Names++
		// directoryName is [4] EXPLICIT Name.
		if v.Class == asn1.ClassContextSpecific && v.Tag == 4 && v.IsCompound {
			name, rest, err := next(v.Bytes)
			if err != nil || !isSequence(name) || len(rest) > 0 {
				return errDER
			}
			is.DirectoryNames = append(is.DirectoryNames, name.FullBytes)
		}
		return nil
	})
	if err != nil {
		return ESSCertIDv2{}, err
	}
	if err := whole(body, &is.Serial); err != nil {
		return ESSCertIDv2{}, err
	}
	id.IssuerSerial = is
	return id, nil
}

// parseInfo reads a TSTInfo: SEQUENCE { version, policy, messageImprint, serialNumber, genTime,
// accuracy OPTIONAL, ordering DEFAULT FALSE, nonce OPTIONAL, tsa [0] OPTIONAL, extensions [1]
// OPTIONAL }, each optional part in its place.
func parseInfo(der []byte) (Info, error) {
	rest, err := sequence(der)
	if err != nil {
		return Info{}, err
	}
	var (
		info    Info
		policy  asn1.RawValue
		imprint messageImprint
		serial  *big.Int
	)
	for _, part := range []any{&info.Version, &policy, &imprint, &serial} {
		if rest, err = asn1.Unmarshal(rest, part); err != nil {
			return Info{}, err
		}
	}
	if _, ok := identifier(policy); !ok || len(imprint.After.FullBytes) > 0 || !imprint.HashAlgorithm.done() {
		return Info{}, errDER
	}
	info.HashAlgorithm, info.HashedMessage = imprint.HashAlgorithm.pkix(), imprint.HashedMessage

	// RFC 3161's GeneralizedTime: seconds always, a fraction with no trailing zero, and Z, DER's form,
	// and a time, its second never 60.
	genTime, rest, err := readElement(rest)
	if err != nil || !genTime.is(asn1.ClassUniversal, tagGeneralizedTime, false) {
		return Info{}, errDER
	}
	var ok bool
	if info.GenTime, ok = instantOf(genTime); !ok {
		return Info{}, errDER
	}

	present := map[byte]bool{}
	optional := func(tag byte, into any) error {
		if t, ok := peek(rest); !ok || t != tag {
			return nil
		}
		present[tag] = true
		var err error
		rest, err = asn1.Unmarshal(rest, into)
		return err
	}
	var (
		accuracy, tsa, extensions asn1.RawValue
		ordering                  bool
		nonce                     *big.Int
	)
	for _, o := range []struct {
		tag  byte
		into any
	}{
		{idSequence, &accuracy},
		{idBoolean, &ordering},
		{idInteger, &nonce},
		{idContext0, &tsa},
		{idContext1, &extensions},
	} {
		if err := optional(o.tag, o.into); err != nil {
			return Info{}, err
		}
	}
	// ordering written out as FALSE, its DEFAULT, is not among the DEFAULTs Timestamps refuses, and
	// ordering is ignored.
	if len(rest) > 0 {
		return Info{}, errDER
	}
	if len(extensions.FullBytes) > 0 {
		err := each(extensions.Bytes, func(v asn1.RawValue) error {
			var e extension
			if err := whole(v.FullBytes, &e); err != nil {
				return err
			}
			// In its one shape: critical written only where it is TRUE, and the value the last element.
			parts, err := elementsOf(v.Bytes)
			id, ok := identifier(e.ID)
			if err != nil || !ok || len(e.After.FullBytes) > 0 || !extensionShaped(parts) {
				return errDER
			}
			// Its value is the DER of one element, with nothing after it, as RFC 3161 writes it, at its
			// depth in the token.
			if err := walk(e.Value, true, depthTSTInfo+infoExtensionValueBelow); err != nil {
				return err
			}
			if _, rest, err := readElement(e.Value); err != nil || len(rest) > 0 {
				return errDER
			}
			info.Extensions = append(info.Extensions, pkix.Extension{Id: id, Critical: e.Critical, Value: e.Value})
			return nil
		})
		if err != nil {
			return Info{}, err
		}
	}
	return info, nil
}

// whole reads der into v, as encoding/asn1 reads it, with nothing after it.
func whole(der []byte, v any) error {
	rest, err := asn1.Unmarshal(der, v)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return errDER
	}
	return nil
}

// next reads the element der begins with, whatever it is.
func next(der []byte) (asn1.RawValue, []byte, error) {
	var v asn1.RawValue
	rest, err := asn1.Unmarshal(der, &v)
	return v, rest, err
}

// each calls f with each element of the contents der, which hold nothing else.
func each(der []byte, f func(asn1.RawValue) error) error {
	for len(der) > 0 {
		v, rest, err := next(der)
		if err != nil {
			return err
		}
		if err := f(v); err != nil {
			return err
		}
		der = rest
	}
	return nil
}

// sequence is the contents of the SEQUENCE der is, with nothing after it.
func sequence(der []byte) ([]byte, error) {
	v, rest, err := next(der)
	if err != nil || !isSequence(v) || len(rest) > 0 {
		return nil, errDER
	}
	return v.Bytes, nil
}

// peek is the identifier byte der begins with, where it has one.
func peek(der []byte) (byte, bool) {
	if len(der) == 0 {
		return 0, false
	}
	return der[0], true
}

// The identifier bytes of the elements the reader peeks at.
const (
	idBoolean  = 0x01
	idInteger  = 0x02
	idSequence = 0x30
	idContext0 = 0xa0
	idContext1 = 0xa1
)

func isSequence(v asn1.RawValue) bool {
	return v.Class == asn1.ClassUniversal && v.Tag == asn1.TagSequence && v.IsCompound
}

func isSet(v asn1.RawValue) bool {
	return v.Class == asn1.ClassUniversal && v.Tag == asn1.TagSet && v.IsCompound
}

// OIDMGF1 is MGF1, the one mask RFC 4055 names for RSASSA-PSS.
var OIDMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}

// PSS is RSASSA-PSS-params (RFC 4055, 3.1), with the defaults it leaves out filled in: SHA-1 for both
// hashes, and a salt of 20 bytes.
type PSS struct {
	// Hash is the signature's hash, and MGF the mask's algorithm, whose hash is MGFHash.
	Hash, MGF, MGFHash asn1.ObjectIdentifier
	// HashParameters and MGFHashParameters are the parameters of each hash's identifier as written,
	// empty where they are absent or the hash is its DEFAULT, left out.
	HashParameters, MGFHashParameters asn1.RawValue
	SaltLength                        int
	TrailerField                      int
}

type pssParams struct {
	Hash         algorithmIdentifier `asn1:"optional,explicit,tag:0"`
	MGF          algorithmIdentifier `asn1:"optional,explicit,tag:1"`
	SaltLength   int                 `asn1:"optional,explicit,tag:2,default:20"`
	TrailerField int                 `asn1:"optional,explicit,tag:3,default:1"`
	After        after               `asn1:"optional"`
}

var oidSHA1 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}

// ParsePSS reads the parameters of an id-RSASSA-PSS signature algorithm.
func ParsePSS(params asn1.RawValue) (PSS, error) {
	var p pssParams
	if err := whole(params.FullBytes, &p); err != nil || len(p.After.FullBytes) > 0 {
		return PSS{}, ErrMalformed
	}
	// Each of hashAlgorithm and maskGenAlgorithm is its DEFAULT where it is left out.
	hash, mgf := len(p.Hash.Algorithm.FullBytes) > 0, len(p.MGF.Algorithm.FullBytes) > 0
	if hash && !p.Hash.done() || mgf && !p.MGF.done() {
		return PSS{}, ErrMalformed
	}
	out := PSS{Hash: oidSHA1, MGF: OIDMGF1, MGFHash: oidSHA1, SaltLength: p.SaltLength, TrailerField: p.TrailerField}
	if hash {
		out.Hash, out.HashParameters = p.Hash.pkix().Algorithm, p.Hash.Parameters
	}
	if mgf {
		var h algorithmIdentifier
		if err := whole(p.MGF.Parameters.FullBytes, &h); err != nil || !h.done() {
			return PSS{}, ErrMalformed
		}
		out.MGF, out.MGFHash, out.MGFHashParameters = p.MGF.pkix().Algorithm, h.pkix().Algorithm, h.Parameters
	}
	return out, nil
}

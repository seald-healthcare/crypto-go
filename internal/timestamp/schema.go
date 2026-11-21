package timestamp

import (
	"encoding/asn1"
	"math/big"
)

// The schemas of RFC 5280 that a token's DER is held to (the Crypto API, Timestamps): every extension
// RFC 5280 §4.2 defines, seventeen, in every certificate a token carries and in every root, whether the
// chain uses it or not, parses as RFC 5280's ASN.1 modules set its schema, with nothing after its value;
// and so do the GeneralNames and PolicyInformation RFC 5035 imports from it into a
// signingCertificateV2, read alike. An extension of any other kind keeps DER's rules that need no schema
// alone.
//
// A schema is read as its module writes it: each field in its order, optional or not, each DEFAULT
// left out, each CHOICE by its tag, each SEQUENCE OF and SET OF of the size it sets, each INTEGER of
// the range it sets, and an implicitly tagged primitive, which the walk cannot tell from a string,
// primitive and of its type's DER. Then:
//
//   - a value of ANY, ANY DEFINED BY among them, is one element under the rules that need no schema
//     alone: a name's AttributeValue, an otherName's value, an extension attribute's value, and a policy
//     qualifier, since PolicyQualifierId is a list RFC 5280 has implementations augment;
//   - a string is read as its universal type, its characters not checked, since the chain compares
//     names byte for byte, and its SIZE is counted in its type's units: two bytes for a BMPString, four
//     for a UniversalString, and a byte for every other, a UTF8String among them, so a string that ends
//     in part of a unit does not parse;
//   - a named bit list keeps no trailing zero bit (X.690, 11.2.2): keyUsage, and a distribution point's
//     reasons.
//
// An ORAddress, x400Address' type, is held to RFC 5280's Appendix A.1, its explicitly tagged module.

// The object identifiers of the extensions RFC 5280 defines for a certificate (4.2.1 and 4.2.2).
var (
	oidAuthorityKeyIdentifier = NewOID(asn1.ObjectIdentifier{2, 5, 29, 35})
	oidCertificatePolicies    = NewOID(asn1.ObjectIdentifier{2, 5, 29, 32})
	oidPolicyMappings         = NewOID(asn1.ObjectIdentifier{2, 5, 29, 33})
	oidSubjectAltName         = NewOID(asn1.ObjectIdentifier{2, 5, 29, 17})
	oidIssuerAltName          = NewOID(asn1.ObjectIdentifier{2, 5, 29, 18})
	oidSubjectDirectoryAttrs  = NewOID(asn1.ObjectIdentifier{2, 5, 29, 9})
	oidNameConstraints        = NewOID(asn1.ObjectIdentifier{2, 5, 29, 30})
	oidPolicyConstraints      = NewOID(asn1.ObjectIdentifier{2, 5, 29, 36})
	oidCRLDistributionPoints  = NewOID(asn1.ObjectIdentifier{2, 5, 29, 31})
	oidInhibitAnyPolicy       = NewOID(asn1.ObjectIdentifier{2, 5, 29, 54})
	oidFreshestCRL            = NewOID(asn1.ObjectIdentifier{2, 5, 29, 46})
	oidAuthorityInfoAccess    = NewOID(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1})
	oidSubjectInfoAccess      = NewOID(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 11})
)

// rfc5280Schemas is each extension RFC 5280 defines, by its object identifier, and whether its value,
// one element, parses as its schema.
var rfc5280Schemas = map[OID]func(element) bool{
	oidAuthorityKeyIdentifier: authorityKeyIdentifier,
	oidSubjectKeyID:           func(e element) bool { return e.is(asn1.ClassUniversal, tagOctetString, false) },
	oidKeyUsage:               keyUsage,
	oidCertificatePolicies:    func(e element) bool { return sequenceOf(e, 1, policyInformation) },
	oidPolicyMappings:         func(e element) bool { return sequenceOf(e, 1, policyMapping) },
	oidSubjectAltName:         generalNames,
	oidIssuerAltName:          generalNames,
	oidSubjectDirectoryAttrs:  func(e element) bool { return sequenceOf(e, 1, attributeShaped) },
	oidBasicConstraints:       basicConstraints,
	oidNameConstraints:        nameConstraints,
	oidPolicyConstraints:      policyConstraints,
	oidExtKeyUsage:            func(e element) bool { return sequenceOf(e, 1, isOID) },
	oidCRLDistributionPoints:  func(e element) bool { return sequenceOf(e, 1, distributionPoint) },
	oidInhibitAnyPolicy:       skipCerts,
	oidFreshestCRL:            func(e element) bool { return sequenceOf(e, 1, distributionPoint) },
	oidAuthorityInfoAccess:    func(e element) bool { return sequenceOf(e, 1, accessDescription) },
	oidSubjectInfoAccess:      func(e element) bool { return sequenceOf(e, 1, accessDescription) },
}

// rfc5280Schema is whether value, an extension's one element, parses as the schema RFC 5280 sets for
// id, and true for an extension RFC 5280 does not define.
func rfc5280Schema(id OID, value element) bool {
	if parses, ok := rfc5280Schemas[id]; ok {
		return parses(value)
	}
	return true
}

// children is the elements of a constructed e's contents, and false where e is primitive or its
// contents are not whole elements.
func children(e element) ([]element, bool) {
	if !e.constructed {
		return nil, false
	}
	parts, err := elementsOf(e.contents)
	return parts, err == nil
}

// sequenceOf is whether e is a SEQUENCE of at least least elements, each of which item parses.
func sequenceOf(e element, least int, item func(element) bool) bool {
	return e.is(asn1.ClassUniversal, tagSequence, true) && holds(e, least, 0, item)
}

// holds is whether constructed e holds from least to most elements, most 0 for no bound, each of which
// item parses, whatever e's tag, for an implicitly tagged SEQUENCE OF or SET OF.
func holds(e element, least, most int, item func(element) bool) bool {
	parts, ok := children(e)
	if !ok || len(parts) < least || most > 0 && len(parts) > most {
		return false
	}
	for _, p := range parts {
		if !item(p) {
			return false
		}
	}
	return true
}

// field is one field of a SEQUENCE's or a SET's schema: whether it is optional, what tells its element,
// and whether that element parses.
type field struct {
	optional bool
	match    func(element) bool
	parses   func(element) bool
}

// fields is whether parts, a SEQUENCE's elements, or a SET's in DER's order, its components' tags', are
// fs in their order: a field takes the next part where its match tells it, and fields fails where that
// part does not parse, a part is left, or a field that is not optional is missing.
func fields(parts []element, fs ...field) bool {
	i := 0
	for _, f := range fs {
		if i < len(parts) && f.match(parts[i]) {
			if !f.parses(parts[i]) {
				return false
			}
			i++
			continue
		}
		if !f.optional {
			return false
		}
	}
	return i == len(parts)
}

// sequenceFields is whether e is a SEQUENCE whose elements are fs.
func sequenceFields(e element, fs ...field) bool {
	parts, ok := children(e)
	return ok && e.is(asn1.ClassUniversal, tagSequence, true) && fields(parts, fs...)
}

// contextTag matches an element of the context class and tag, of either form.
func contextTag(tag int) func(element) bool {
	return func(e element) bool { return e.class == asn1.ClassContextSpecific && e.tag == tag }
}

// applicationTag matches an element of the application class and tag, of either form.
func applicationTag(tag int) func(element) bool {
	return func(e element) bool { return e.class == asn1.ClassApplication && e.tag == tag }
}

// universal matches a universal element of tag, of either form.
func universal(tag int) func(element) bool {
	return func(e element) bool { return e.class == asn1.ClassUniversal && e.tag == tag }
}

// anything is a value of ANY: one element, which the walk holds to the rules that need no schema.
func anything(element) bool { return true }

func isOID(e element) bool { return e.is(asn1.ClassUniversal, tagOID, false) }

func isInteger(e element) bool { return e.is(asn1.ClassUniversal, tagInteger, false) }

// nonNegative is whether c, an INTEGER's contents in DER, is 0 or more: INTEGER (0..MAX).
func nonNegative(c []byte) bool { return minimalInteger(c) && c[0]&0x80 == 0 }

// skipCerts is SkipCerts and BaseDistance, an INTEGER (0..MAX).
func skipCerts(e element) bool { return isInteger(e) && nonNegative(e.contents) }

// implicitInteger is an INTEGER implicitly tagged: primitive, minimal, and 0 or more where
// onlyNonNegative is set.
func implicitInteger(e element, onlyNonNegative bool) bool {
	return !e.constructed && minimalInteger(e.contents) && (!onlyNonNegative || e.contents[0]&0x80 == 0)
}

// implicitBitString is a BIT STRING implicitly tagged, in DER's form: primitive, its unused bits
// counted in its first byte, at most 7, and zero.
func implicitBitString(e element) bool {
	c := e.contents
	return !e.constructed && len(c) > 0 && c[0] <= 7 && (len(c) > 1 || c[0] == 0) && c[len(c)-1]&(1<<c[0]-1) == 0
}

// namedBitList is whether e, a BIT STRING in DER's form, keeps no trailing zero bit, as DER writes a
// named bit list (X.690, 11.2.2): its last bit is set, where it has any.
func namedBitList(e element) bool {
	c := e.contents
	return len(c) == 1 || c[len(c)-1]>>c[0]&1 == 1
}

// keyUsage is KeyUsage, a named bit list.
func keyUsage(e element) bool {
	return e.is(asn1.ClassUniversal, tagBitString, false) && namedBitList(e)
}

// String tags of the types the schemas name.
const (
	tagNumericString   = 18
	tagPrintableString = 19
	tagTeletexString   = 20
	tagIA5String       = 22
	tagUniversalString = 28
	tagBMPString       = 30
)

// units is how many units of its type e's contents hold, a string's SIZE: two bytes for a BMPString,
// four for a UniversalString, and a byte for every other, and false where its contents end in part of
// a unit.
func units(tag int, contents []byte) (int, bool) {
	switch tag {
	case tagBMPString:
		return len(contents) / 2, len(contents)%2 == 0
	case tagUniversalString:
		return len(contents) / 4, len(contents)%4 == 0
	}
	return len(contents), true
}

// sized is whether contents hold from least to most units of the string type tag, most 0 for no bound.
func sized(tag int, contents []byte, least, most int) bool {
	n, ok := units(tag, contents)
	return ok && n >= least && (most == 0 || n <= most)
}

// size is a string type and the SIZE a schema sets of it, most 0 for no bound.
type size struct{ tag, least, most int }

// stringOf is whether e is a universal string of one of choices, holding as many units as its SIZE
// sets. Its characters are not checked.
func stringOf(e element, choices ...size) bool {
	if e.class != asn1.ClassUniversal || e.constructed {
		return false
	}
	for _, s := range choices {
		if e.tag == s.tag {
			return sized(s.tag, e.contents, s.least, s.most)
		}
	}
	return false
}

// implicitString is a string of type tag implicitly tagged, of the SIZE least to most: primitive, and
// counted in its type's units.
func implicitString(tag, least, most int) func(element) bool {
	return func(e element) bool { return !e.constructed && sized(tag, e.contents, least, most) }
}

// generalNames is GeneralNames: SEQUENCE SIZE (1..MAX) OF GeneralName.
func generalNames(e element) bool { return sequenceOf(e, 1, generalName) }

// generalName is GeneralName, each choice by its tag, implicitly tagged but for directoryName, a Name,
// which is a CHOICE and so explicitly tagged.
func generalName(e element) bool {
	if e.class != asn1.ClassContextSpecific {
		return false
	}
	switch e.tag {
	case 0: // otherName, AnotherName: SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY }
		parts, ok := children(e)
		return ok && fields(parts,
			field{match: universal(tagOID), parses: isOID},
			field{match: contextTag(0), parses: explicitly(anything)})
	case 1, 2, 6: // rfc822Name, dNSName, uniformResourceIdentifier: IA5String
		return !e.constructed
	case 3: // x400Address, ORAddress
		parts, ok := children(e)
		return ok && orAddress(parts)
	case 4: // directoryName, Name
		return explicitly(distinguishedName)(e)
	case 5: // ediPartyName: SEQUENCE { nameAssigner [0] DirectoryString OPTIONAL, partyName [1] DirectoryString }
		parts, ok := children(e)
		return ok && fields(parts,
			field{optional: true, match: contextTag(0), parses: explicitly(directoryString)},
			field{match: contextTag(1), parses: explicitly(directoryString)})
	case 7: // iPAddress: OCTET STRING
		return !e.constructed
	case 8: // registeredID: OBJECT IDENTIFIER
		return !e.constructed && minimalSubidentifiers(e.contents)
	}
	return false
}

// explicitly is a field explicitly tagged around one element that parses.
func explicitly(parses func(element) bool) func(element) bool {
	return func(e element) bool {
		parts, ok := children(e)
		return ok && len(parts) == 1 && parses(parts[0])
	}
}

// directoryString is DirectoryString: a CHOICE of TeletexString, PrintableString, UniversalString,
// UTF8String and BMPString, each SIZE (1..MAX).
func directoryString(e element) bool {
	return stringOf(e, size{tagTeletexString, 1, 0}, size{tagPrintableString, 1, 0}, size{tagUniversalString, 1, 0},
		size{tagUTF8String, 1, 0}, size{tagBMPString, 1, 0})
}

// distinguishedName is Name, a CHOICE of RDNSequence alone: SEQUENCE OF RelativeDistinguishedName.
func distinguishedName(e element) bool { return sequenceOf(e, 0, relativeDistinguishedName) }

// relativeDistinguishedName is SET SIZE (1..MAX) OF AttributeTypeAndValue, which the walk holds to
// DER's order.
func relativeDistinguishedName(e element) bool {
	return e.is(asn1.ClassUniversal, tagSet, true) && holds(e, 1, 0, attributeTypeAndValue)
}

// attributeTypeAndValue is SEQUENCE { type OBJECT IDENTIFIER, value ANY }.
func attributeTypeAndValue(e element) bool {
	return sequenceFields(e, field{match: universal(tagOID), parses: isOID}, field{match: anything, parses: anything})
}

// attributeShaped is RFC 5280's Attribute, and RFC 5652's alike: SEQUENCE { type OBJECT IDENTIFIER, values
// SET OF ANY }, each value one element, the SET in DER's order, which the walk holds it to.
func attributeShaped(e element) bool {
	return sequenceFields(e,
		field{match: universal(tagOID), parses: isOID},
		field{match: universal(tagSet), parses: func(v element) bool { return v.constructed }})
}

// authorityKeyIdentifier is SEQUENCE { keyIdentifier [0] OCTET STRING OPTIONAL, authorityCertIssuer
// [1] GeneralNames OPTIONAL, authorityCertSerialNumber [2] INTEGER OPTIONAL }.
func authorityKeyIdentifier(e element) bool {
	return sequenceFields(e,
		field{optional: true, match: contextTag(0), parses: func(v element) bool { return !v.constructed }},
		field{optional: true, match: contextTag(1), parses: func(v element) bool { return holds(v, 1, 0, generalName) }},
		field{optional: true, match: contextTag(2), parses: func(v element) bool { return implicitInteger(v, false) }})
}

// policyInformation is SEQUENCE { policyIdentifier OBJECT IDENTIFIER, policyQualifiers SEQUENCE SIZE
// (1..MAX) OF PolicyQualifierInfo OPTIONAL }.
func policyInformation(e element) bool {
	return sequenceFields(e,
		field{match: universal(tagOID), parses: isOID},
		field{optional: true, match: universal(tagSequence), parses: func(v element) bool { return sequenceOf(v, 1, policyQualifierInfo) }})
}

// policyQualifierInfo is SEQUENCE { policyQualifierId OBJECT IDENTIFIER, qualifier ANY DEFINED BY
// policyQualifierId }. PolicyQualifierId names id-qt-cps and id-qt-unotice, a list RFC 5280 has
// implementations augment, so a qualifier of any id parses, and its qualifier is one element.
func policyQualifierInfo(e element) bool {
	return sequenceFields(e, field{match: universal(tagOID), parses: isOID}, field{match: anything, parses: anything})
}

// policyMapping is SEQUENCE { issuerDomainPolicy OBJECT IDENTIFIER, subjectDomainPolicy OBJECT
// IDENTIFIER }.
func policyMapping(e element) bool {
	return sequenceFields(e, field{match: universal(tagOID), parses: isOID}, field{match: universal(tagOID), parses: isOID})
}

// basicConstraints is SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX)
// OPTIONAL }, cA never written out as its DEFAULT.
func basicConstraints(e element) bool {
	return sequenceFields(e,
		field{optional: true, match: universal(tagBoolean), parses: func(v element) bool { return !explicitFalse(v) }},
		field{optional: true, match: universal(tagInteger), parses: skipCerts})
}

// nameConstraints is SEQUENCE { permittedSubtrees [0] GeneralSubtrees OPTIONAL, excludedSubtrees [1]
// GeneralSubtrees OPTIONAL }, each SEQUENCE SIZE (1..MAX) OF GeneralSubtree.
func nameConstraints(e element) bool {
	subtrees := func(v element) bool { return holds(v, 1, 0, generalSubtree) }
	return sequenceFields(e,
		field{optional: true, match: contextTag(0), parses: subtrees},
		field{optional: true, match: contextTag(1), parses: subtrees})
}

// generalSubtree is SEQUENCE { base GeneralName, minimum [0] BaseDistance DEFAULT 0, maximum [1]
// BaseDistance OPTIONAL }, minimum never written out as its DEFAULT. base's tags are [0] to [8], so a
// part after it is told by its place.
func generalSubtree(e element) bool {
	parts, ok := children(e)
	if !e.is(asn1.ClassUniversal, tagSequence, true) || !ok || len(parts) == 0 || !generalName(parts[0]) {
		return false
	}
	distance := func(v element) bool { return implicitInteger(v, true) }
	minimum := func(v element) bool { return distance(v) && (len(v.contents) != 1 || v.contents[0] != 0) }
	return fields(parts[1:],
		field{optional: true, match: contextTag(0), parses: minimum},
		field{optional: true, match: contextTag(1), parses: distance})
}

// policyConstraints is SEQUENCE { requireExplicitPolicy [0] SkipCerts OPTIONAL, inhibitPolicyMapping
// [1] SkipCerts OPTIONAL }.
func policyConstraints(e element) bool {
	skip := func(v element) bool { return implicitInteger(v, true) }
	return sequenceFields(e,
		field{optional: true, match: contextTag(0), parses: skip},
		field{optional: true, match: contextTag(1), parses: skip})
}

// distributionPoint is SEQUENCE { distributionPoint [0] DistributionPointName OPTIONAL, reasons [1]
// ReasonFlags OPTIONAL, cRLIssuer [2] GeneralNames OPTIONAL }. DistributionPointName is a CHOICE, so
// its tag is explicit: fullName [0] GeneralNames, or nameRelativeToCRLIssuer [1] RelativeDistinguishedName,
// a SET OF in DER's order. ReasonFlags is a named bit list.
func distributionPoint(e element) bool {
	pointName := func(v element) bool {
		switch {
		case v.is(asn1.ClassContextSpecific, 0, true):
			return holds(v, 1, 0, generalName)
		case v.is(asn1.ClassContextSpecific, 1, true):
			return holds(v, 1, 0, attributeTypeAndValue) && inOrder(v.contents) == nil
		}
		return false
	}
	return sequenceFields(e,
		field{optional: true, match: contextTag(0), parses: explicitly(pointName)},
		field{optional: true, match: contextTag(1), parses: func(v element) bool { return implicitBitString(v) && namedBitList(v) }},
		field{optional: true, match: contextTag(2), parses: func(v element) bool { return holds(v, 1, 0, generalName) }})
}

// accessDescription is SEQUENCE { accessMethod OBJECT IDENTIFIER, accessLocation GeneralName }.
func accessDescription(e element) bool {
	return sequenceFields(e, field{match: universal(tagOID), parses: isOID}, field{match: anything, parses: generalName})
}

// The upper bounds RFC 5280's Appendix A.1 takes from X.411 for an ORAddress.
const (
	ubCountryNameAlpha        = 2
	ubCountryNameNumeric      = 3
	ubDomainDefinedAttributes = 4
	ubDomainAttributeType     = 8
	ubDomainAttributeValue    = 128
	ubDomainName              = 16
	ubExtensionAttributes     = 256
	ubGenerationQualifier     = 3
	ubGivenName               = 16
	ubInitials                = 5
	ubNumericUserID           = 32
	ubOrganizationName        = 64
	ubOrganizationalUnitName  = 32
	ubOrganizationalUnits     = 4
	ubSurname                 = 40
	ubTerminalID              = 24
	ubX121Address             = 16
)

// orAddress is whether parts, an x400Address' [3] IMPLICIT contents, are an ORAddress, as RFC 5280's
// Appendix A.1 sets it in its explicitly tagged module:
//
//	ORAddress ::= SEQUENCE { built-in-standard-attributes BuiltInStandardAttributes,
//	  built-in-domain-defined-attributes BuiltInDomainDefinedAttributes OPTIONAL,
//	  extension-attributes ExtensionAttributes OPTIONAL }
func orAddress(parts []element) bool {
	return fields(parts,
		field{match: universal(tagSequence), parses: builtInStandardAttributes},
		field{optional: true, match: universal(tagSequence), parses: builtInDomainDefinedAttributes},
		field{optional: true, match: universal(tagSet), parses: extensionAttributes})
}

// builtInStandardAttributes is SEQUENCE { country-name CountryName OPTIONAL,
// administration-domain-name AdministrationDomainName OPTIONAL, network-address [0] IMPLICIT
// NetworkAddress OPTIONAL, terminal-identifier [1] IMPLICIT TerminalIdentifier OPTIONAL,
// private-domain-name [2] PrivateDomainName OPTIONAL, organization-name [3] IMPLICIT OrganizationName
// OPTIONAL, numeric-user-identifier [4] IMPLICIT NumericUserIdentifier OPTIONAL, personal-name [5]
// IMPLICIT PersonalName OPTIONAL, organizational-unit-names [6] IMPLICIT OrganizationalUnitNames
// OPTIONAL }. CountryName is [APPLICATION 1] and AdministrationDomainName [APPLICATION 2], each a CHOICE,
// as PrivateDomainName is, so each of the three is tagged explicitly.
func builtInStandardAttributes(e element) bool {
	numericOrPrintable := func(least, most int) func(element) bool {
		return func(v element) bool {
			return stringOf(v, size{tagNumericString, least, most}, size{tagPrintableString, least, most})
		}
	}
	country := func(v element) bool {
		return stringOf(v, size{tagNumericString, ubCountryNameNumeric, ubCountryNameNumeric},
			size{tagPrintableString, ubCountryNameAlpha, ubCountryNameAlpha})
	}
	return sequenceFields(e,
		field{optional: true, match: applicationTag(1), parses: explicitly(country)},
		field{optional: true, match: applicationTag(2), parses: explicitly(numericOrPrintable(0, ubDomainName))},
		field{optional: true, match: contextTag(0), parses: implicitString(tagNumericString, 1, ubX121Address)},
		field{optional: true, match: contextTag(1), parses: implicitString(tagPrintableString, 1, ubTerminalID)},
		field{optional: true, match: contextTag(2), parses: explicitly(numericOrPrintable(1, ubDomainName))},
		field{optional: true, match: contextTag(3), parses: implicitString(tagPrintableString, 1, ubOrganizationName)},
		field{optional: true, match: contextTag(4), parses: implicitString(tagNumericString, 1, ubNumericUserID)},
		field{optional: true, match: contextTag(5), parses: personalName},
		field{optional: true, match: contextTag(6), parses: func(v element) bool {
			return holds(v, 1, ubOrganizationalUnits, func(u element) bool {
				return stringOf(u, size{tagPrintableString, 1, ubOrganizationalUnitName})
			})
		}})
}

// personalName is PersonalName, [5] IMPLICIT: SET { surname [0] IMPLICIT PrintableString, given-name
// [1] IMPLICIT PrintableString OPTIONAL, initials [2] IMPLICIT PrintableString OPTIONAL,
// generation-qualifier [3] IMPLICIT PrintableString OPTIONAL }, each of its SIZE, in DER's order of a
// SET, its tags'.
func personalName(e element) bool {
	parts, ok := children(e)
	return ok && fields(parts,
		field{match: contextTag(0), parses: implicitString(tagPrintableString, 1, ubSurname)},
		field{optional: true, match: contextTag(1), parses: implicitString(tagPrintableString, 1, ubGivenName)},
		field{optional: true, match: contextTag(2), parses: implicitString(tagPrintableString, 1, ubInitials)},
		field{optional: true, match: contextTag(3), parses: implicitString(tagPrintableString, 1, ubGenerationQualifier)})
}

// builtInDomainDefinedAttributes is SEQUENCE SIZE (1..ub-domain-defined-attributes) OF SEQUENCE {
// type PrintableString, value PrintableString }, each of its SIZE.
func builtInDomainDefinedAttributes(e element) bool {
	return e.is(asn1.ClassUniversal, tagSequence, true) && holds(e, 1, ubDomainDefinedAttributes, func(a element) bool {
		return sequenceFields(a,
			field{match: universal(tagPrintableString), parses: func(v element) bool {
				return stringOf(v, size{tagPrintableString, 1, ubDomainAttributeType})
			}},
			field{match: universal(tagPrintableString), parses: func(v element) bool {
				return stringOf(v, size{tagPrintableString, 1, ubDomainAttributeValue})
			}})
	})
}

// extensionAttributes is SET SIZE (1..ub-extension-attributes) OF SEQUENCE { extension-attribute-type
// [0] IMPLICIT INTEGER (0..ub-extension-attributes), extension-attribute-value [1] ANY DEFINED BY
// extension-attribute-type }, its value one element, explicitly tagged, and the SET in DER's order,
// which the walk holds it to.
func extensionAttributes(e element) bool {
	attributeType := func(v element) bool {
		return implicitInteger(v, true) && new(big.Int).SetBytes(v.contents).Cmp(big.NewInt(ubExtensionAttributes)) <= 0
	}
	return e.is(asn1.ClassUniversal, tagSet, true) && holds(e, 1, ubExtensionAttributes, func(a element) bool {
		return sequenceFields(a,
			field{match: contextTag(0), parses: attributeType},
			field{match: contextTag(1), parses: explicitly(anything)})
	})
}

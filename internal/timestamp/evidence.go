package timestamp

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

// EvidenceRecord is what an RFC 4998 EvidenceRecord holds, of the parts its verification reads: the
// hashes it names, and each chain of archive timestamps, in its order. Its cryptoInfos and each archive
// timestamp's attributes are read for their form, and not kept.
type EvidenceRecord struct {
	DigestAlgorithms []pkix.AlgorithmIdentifier
	Chains           [][]ArchiveTimeStamp
}

// ArchiveTimeStamp is an archive timestamp: its hash where it names one, its reduced hash tree, each
// list of hash values in its order, nil where it has none, and its timeStamp, TimeStamp its DER and
// Token the token it parses as.
type ArchiveTimeStamp struct {
	DigestAlgorithm *pkix.AlgorithmIdentifier
	ReducedHashtree [][][]byte
	TimeStamp       []byte
	Token           *Token
}

// The depths, as Renewal counts them, of the parts of a record walked on their own: an
// EvidenceRecord's fields, inside it at depth 1, and an archive timestamp's fields but its timeStamp,
// inside the archive timestamp, its chain and the record's archiveTimeStampSequence.
const (
	depthRecordField           = 2
	depthArchiveTimeStampField = 5
)

// ParseEvidenceRecord reads der as RFC 4998's EvidenceRecord, its module's tags implicit:
//
//	EvidenceRecord ::= SEQUENCE {
//	  version INTEGER { v1(1) }, digestAlgorithms SEQUENCE OF AlgorithmIdentifier,
//	  cryptoInfos [0] SEQUENCE SIZE (1..MAX) OF Attribute OPTIONAL,
//	  encryptionInfo [1] EncryptionInfo OPTIONAL,
//	  archiveTimeStampSequence SEQUENCE OF SEQUENCE OF ArchiveTimeStamp }
//	ArchiveTimeStamp ::= SEQUENCE {
//	  digestAlgorithm [0] AlgorithmIdentifier OPTIONAL, attributes [1] SET SIZE (1..MAX) OF Attribute
//	  OPTIONAL, reducedHashtree [2] SEQUENCE OF SEQUENCE OF OCTET STRING OPTIONAL, timeStamp ContentInfo }
//
// as Renewal sets it: of version 1, read as DER, as a token is, every element keeping DER's rules that
// need no schema, nested at most 64 deep, its EvidenceRecord at depth 1, and each timeStamp parsing as a
// token does, counted from its own ContentInfo, as a token given alone is, so a token nests alike alone
// and in a record. It has no encryptionInfo, since its data object is in the clear. Its cryptoInfos and
// each archive timestamp's attributes are read for their form alone: one or more of RFC 5652's
// Attribute, an object identifier and a SET OF values, each value one element. An archive timestamp's
// attributes, an implicitly tagged SET OF nothing signs, are in any order, and a SET inside an
// attribute keeps DER's order. A record of zero bytes does not parse. Every error is ErrMalformed, and
// quotes nothing of the record.
func ParseEvidenceRecord(der []byte) (*EvidenceRecord, error) {
	r, ok := evidenceRecord(der)
	if !ok {
		return nil, ErrMalformed
	}
	return r, nil
}

// attributes is whether e, implicitly tagged, holds one or more of RFC 5652's Attribute.
func attributes(e element) bool { return holds(e, 1, 0, attributeShaped) }

func evidenceRecord(der []byte) (*EvidenceRecord, bool) {
	e, rest, err := readElement(der)
	if err != nil || len(rest) > 0 || !e.is(asn1.ClassUniversal, tagSequence, true) {
		return nil, false
	}
	parts, ok := children(e)
	if !ok {
		return nil, false
	}
	// Every field is walked at its depth, but archiveTimeStampSequence, which is walked to each token.
	for _, p := range parts[:max(len(parts)-1, 0)] {
		if walk(p.full, true, depthRecordField) != nil {
			return nil, false
		}
	}
	r := &EvidenceRecord{}
	var sequence element
	if !fields(parts,
		field{match: universal(tagInteger), parses: func(v element) bool {
			return isInteger(v) && len(v.contents) == 1 && v.contents[0] == 1
		}},
		field{match: universal(tagSequence), parses: func(v element) bool {
			return sequenceOf(v, 0, func(a element) bool {
				id, ok := algorithm(a)
				r.DigestAlgorithms = append(r.DigestAlgorithms, id)
				return ok
			})
		}},
		field{optional: true, match: contextTag(0), parses: attributes},
		// encryptionInfo [1] has no field: a record holding one does not parse.
		field{match: universal(tagSequence), parses: func(v element) bool { sequence = v; return v.constructed }},
	) {
		return nil, false
	}
	if !sequenceOf(sequence, 0, func(c element) bool {
		var chain []ArchiveTimeStamp
		ok := sequenceOf(c, 0, func(a element) bool {
			ats, ok := archiveTimeStamp(a)
			chain = append(chain, ats)
			return ok
		})
		r.Chains = append(r.Chains, chain)
		return ok
	}) {
		return nil, false
	}
	return r, true
}

func archiveTimeStamp(e element) (ArchiveTimeStamp, bool) {
	var a ArchiveTimeStamp
	parts, ok := children(e)
	if !e.is(asn1.ClassUniversal, tagSequence, true) || !ok {
		return a, false
	}
	for _, p := range parts[:max(len(parts)-1, 0)] {
		if walk(p.full, true, depthArchiveTimeStampField) != nil {
			return a, false
		}
	}
	ok = fields(parts,
		field{optional: true, match: contextTag(0), parses: func(v element) bool {
			// [0] IMPLICIT AlgorithmIdentifier: its contents are the identifier's.
			id, ok := algorithm(element{class: asn1.ClassUniversal, tag: tagSequence, constructed: v.constructed, contents: v.contents})
			a.DigestAlgorithm = &id
			return ok
		}},
		field{optional: true, match: contextTag(1), parses: attributes},
		field{optional: true, match: contextTag(2), parses: func(v element) bool {
			a.ReducedHashtree = [][][]byte{}
			return holds(v, 0, 0, func(list element) bool {
				var hashes [][]byte
				ok := sequenceOf(list, 0, func(h element) bool {
					hashes = append(hashes, h.contents)
					return h.is(asn1.ClassUniversal, tagOctetString, false)
				})
				a.ReducedHashtree = append(a.ReducedHashtree, hashes)
				return ok
			})
		}},
		field{match: universal(tagSequence), parses: func(v element) bool {
			t, err := parse(v.full)
			a.TimeStamp, a.Token = v.full, t
			return err == nil
		}},
	)
	return a, ok
}

// algorithm is the AlgorithmIdentifier e is: SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY
// OPTIONAL }. An identifier of an arc past 2^31 is nil, which names no hash.
func algorithm(e element) (pkix.AlgorithmIdentifier, bool) {
	parts, ok := children(e)
	if !algorithmIdentifier5280(e) || !ok {
		return pkix.AlgorithmIdentifier{}, false
	}
	var a pkix.AlgorithmIdentifier
	a.Algorithm, _ = identifier(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagOID, FullBytes: parts[0].full})
	if len(parts) == 2 {
		a.Parameters = asn1.RawValue{FullBytes: parts[1].full}
	}
	return a, true
}

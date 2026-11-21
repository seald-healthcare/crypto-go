package verify

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509/pkix"
	"slices"

	"github.com/seald-healthcare/crypto-go/internal/refusal"
	"github.com/seald-healthcare/crypto-go/internal/timestamp"
)

// verifyEvidenceRecord checks record, an RFC 4998 EvidenceRecord given with token, a token over head
// that verifies under roots, as the Crypto API's Renewal sets, and refuses timestamp-invalid one that
// does not verify as RFC 4998, 5.3, sets:
//
//   - it parses as Renewal reads RFC 4998's EvidenceRecord: as DER, as a token is, nested at most 64
//     deep, of version 1, with no encryptionInfo, its cryptoInfos and each archive timestamp's
//     attributes of their form alone, and every archive timestamp parsing as a token does; a record of
//     zero bytes does not parse;
//   - every hash it names is SHA-256, its only hash;
//   - it holds one chain of archive timestamps, since only a hash-tree renewal makes a second;
//   - its first archive timestamp is the token, byte for byte, and covers head, the hash of its data
//     object;
//   - each later one names SHA-256 where it names a hash, and covers the hash of the token of the one
//     before through its reduced hash tree, as RFC 4998, 4.3, computes a root, a list of one hash among
//     it, and was taken before the date of the one before, the end of 2035;
//   - the last is accepted as Timestamps sets a token over that root, under the same roots, by the
//     platform's clock, and each before it is read for its imprint and genTime alone, its signature,
//     chain and date unchecked.
//
// A record that fails is never kept as if it held: the token it was given with is refused with it.
func verifyEvidenceRecord(record, token, head []byte, roots []*chainCert) error {
	r, err := timestamp.ParseEvidenceRecord(record)
	if err != nil {
		return refusal.New(invalid, "an evidence record that does not parse")
	}
	if len(r.DigestAlgorithms) == 0 || slices.ContainsFunc(r.DigestAlgorithms, func(a pkix.AlgorithmIdentifier) bool { return !isSHA256(a) }) {
		return refusal.New(invalid, "an evidence record of a hash other than SHA-256")
	}
	if len(r.Chains) != 1 {
		return refusal.New(invalid, "an evidence record of other than one chain of archive timestamps")
	}
	chain := r.Chains[0]
	if len(chain) == 0 || !bytes.Equal(chain[0].TimeStamp, token) {
		return refusal.New(invalid, "an evidence record whose first archive timestamp is not the token")
	}
	for i, ats := range chain {
		if ats.DigestAlgorithm != nil && !isSHA256(*ats.DigestAlgorithm) {
			return refusal.New(invalid, "an archive timestamp of a hash other than SHA-256")
		}
		covered := head
		if i > 0 {
			h := sha256.Sum256(chain[i-1].TimeStamp)
			covered = h[:]
		}
		root, ok := reducedRoot(covered, ats.ReducedHashtree)
		if !ok {
			return refusal.New(invalid, "an archive timestamp whose reduced hash tree does not hold what it covers")
		}
		switch {
		case i == 0:
			// The token, verified in full by the caller, is over head, which the root of its tree must be.
			if !bytes.Equal(root, head) {
				return refusal.New(invalid, "an evidence record whose first archive timestamp does not cover its data object")
			}
			continue
		case i == len(chain)-1:
			if _, err := verifyTimestamp(ats.TimeStamp, root, roots); err != nil {
				return refusal.New(invalid, "an archive timestamp Timestamps does not accept")
			}
		default:
			// Read for its imprint and genTime alone.
			info := ats.Token.Info
			if !isSHA256(info.HashAlgorithm) || !bytes.Equal(info.HashedMessage, root) {
				return refusal.New(invalid, "an archive timestamp over another hash than the one before's")
			}
		}
		if !ats.Token.Info.GenTime.Floor().Before(signatureDate) {
			return refusal.New(invalid, "an archive timestamp taken past the date of the one before")
		}
	}
	return nil
}

// reducedRoot is the root hash value RFC 4998, 4.3, computes of covered through tree: covered is in the
// first list, and the SHA-256 of each list's hash values, concatenated in binary ascending order, is in
// the next, up to the root, a list of one hash hashed as any other. An archive timestamp with no list
// covers covered itself.
func reducedRoot(covered []byte, tree [][][]byte) ([]byte, bool) {
	h := covered
	for _, list := range tree {
		if !slices.ContainsFunc(list, func(v []byte) bool { return bytes.Equal(v, h) }) {
			return nil, false
		}
		sorted := slices.Clone(list)
		slices.SortFunc(sorted, bytes.Compare)
		sum := sha256.Sum256(bytes.Join(sorted, nil))
		h = sum[:]
	}
	return h, true
}

func isSHA256(a pkix.AlgorithmIdentifier) bool {
	return a.Algorithm.Equal(oidSHA256) && absentOrNull(a.Parameters)
}

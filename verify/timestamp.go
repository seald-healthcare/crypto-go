package verify

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math"
	"math/big"
	"slices"
	"time"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
	"github.com/seald-healthcare/crypto-go/internal/timestamp"
)

// signatureDate is when a token's signature stops being accepted: the end of 2035, after which NIST IR
// 8547 disallows ECDSA and RSA alike. A token is accepted while the system clock reads before it.
var signatureDate = time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)

// now is the system clock, which VerifyTimestamp reads itself, never a time the caller passes, and
// a test fixes.
var now = time.Now

// VerifyTimestampResult is what VerifyTimestamp returns.
type VerifyTimestampResult struct {
	// Time is the token's genTime, in UTC, rounded up to the next whole second where it gives a
	// fraction, since a token proves existence at or before its time.
	Time time.Time
}

// VerifyTimestamp is the vectors' verifyTimestamp: token, an RFC 3161 TimeStampToken, checked over head
// under one of roots, and its time returned. It accepts a token when:
//
//   - every element of it, read or not, keeps DER's rules that need no schema: minimal definite
//     lengths, primitive strings, minimal integers and object identifiers, booleans, a BIT STRING's
//     padding, DER's time forms, and each SET OF in DER's order, the signed attributes among them, but
//     for the SignedData's certificates and CRLs and a signer info's unsigned attributes, each
//     implicitly tagged, in any order; it nests at most 64 deep, its ContentInfo depth 1 and an element
//     inside an OCTET STRING that holds DER, the TSTInfo and an extension's value, one deeper than that
//     OCTET STRING; and in its TSTInfo, its signed attributes, its signer info and each certificate it
//     carries, no DEFAULT is written out of those Timestamps lists: a certificate's version v1, an
//     extension's critical FALSE, basicConstraints' cA FALSE, a GeneralSubtree's minimum 0, a field of
//     RSASSA-PSS-params at its DEFAULT where the parameters parse as that type, the trailing zero bits of every named bit list, keyUsage's and a distribution
//     point's reasons, and an ESSCertIDv2's id-sha256 with its parameters absent, which with NULL
//     parameters is another value, and accepted; the TSTInfo's ordering written out as FALSE is
//     accepted;
//   - each certificate it carries holds X.509's ASN.1 alone outside its extensions, each
//     AlgorithmIdentifier an object identifier and at most its parameters, its subjectPublicKeyInfo an
//     AlgorithmIdentifier and a BIT STRING, a name's AttributeValue one element, and after its key
//     issuerUniqueID, subjectUniqueID and extensions, in that order and each at most once, so a version
//     above v3, a serial that is not positive, a name's characters outside its string type, a path
//     length of any size and a validity time with a fraction of a second parse; its signature is its
//     signatureAlgorithm, byte for byte; it holds no extension twice; and no time in it, nor its
//     genTime, has a second of 60;
//   - each extension's value, in the TSTInfo and in each certificate it carries, is one element with
//     nothing after it, and each of the seventeen extensions RFC 5280 §4.2 defines, in each
//     certificate it carries, whether the chain uses it or not, parses as RFC 5280's ASN.1 modules set
//     its schema, an ORAddress as its Appendix A.1 does: every type, tag, OPTIONAL and DEFAULT, CHOICE,
//     SEQUENCE OF and SET OF, and every SIZE and value constraint, a policy qualifier of any id, a value
//     of ANY one element, and a string read as its universal type, its characters not checked and its
//     SIZE counted in its type's units, so a BMPString of an odd length does not parse;
//   - its SignedData is of version 3, and carries at most eight certificates, each of a form of RFC
//     5652's CertificateChoices by its constructed tag alone, of which those in X.509 alone are read,
//     and any other form, and a CRL, ignored; an element of no form does not parse;
//   - its imprint is SHA-256 and its hashedMessage is head;
//   - its TSTInfo is of version 1, and has no critical extension;
//   - it has exactly one signer info, of version 1 naming its signer by issuer and serial number or of
//     version 3 by subject key identifier, whose signed attributes hold one contentType, TSTInfo's, one
//     messageDigest, the digest of the TSTInfo, and one signingCertificateV2, each parsing as RFC 5652
//     and RFC 5035 set its schema, every ESSCertIDv2 and its policies among it, read as an extension's
//     schema is, whose first ESSCertIDv2 binds the signer's certificate under SHA-256, SHA-384 or
//     SHA-512, and where it has an issuerSerial, names in it one GeneralName, a directoryName byte for
//     byte that certificate's issuer, and its serial number;
//   - its signature verifies under the signer's certificate, which the token carries: ECDSA on P-256
//     or P-384, or RSA of 3072 bits or more under PKCS #1 v1.5 or PSS, over SHA-256, SHA-384 or
//     SHA-512, the hash its digestAlgorithm names, PSS's for its signature and its mask alike, each
//     hash identifier's parameters absent or NULL, with a salt of that hash's length;
//   - the signer's certificate carries the time-stamping extended key usage, critical or not and alone
//     or not, and chains to one of roots through the certificates the token carries, in a chain of at
//     most eight, as RFC 5280's path validation checks a chain but for revocation, policies and name
//     constraints, at the exact genTime: each certificate valid at it, each time compared exactly, its
//     key an uncompressed ECDSA point on P-256 or P-384 under id-ecPublicKey naming its curve, or RSA of
//     2048 bits or more, an RSAPublicKey, under rsaEncryption with NULL parameters, its issuer byte for
//     byte its signer's subject, and signed over SHA-256 or longer, under ECDSA with its
//     signatureAlgorithm's parameters absent, under PKCS #1 v1.5 with them absent or NULL, or under
//     id-RSASSA-PSS with parameters naming that hash for the signature and for MGF1 and a salt of its
//     length, but for the root, which signs itself unchecked; each that signs another a CA whose keyUsage, where it has one, even of no
//     bit set, sets keyCertSign, within its path length; and none with a critical extension but
//     basicConstraints, keyUsage and extendedKeyUsage. The extended key usage is checked on the
//     signer's certificate alone, and every certificate's extensions are read whatever its version. A
//     carried certificate whose key is in another form, a point off its curve, an rsaEncryption key
//     that is no RSAPublicKey or a key in a BIT STRING of unused bits among them, gives the chain
//     nothing, and fails no parse: all else of it parses as X.509 all the same. A signature in a BIT
//     STRING of unused bits, and one under a signature algorithm of other parameters, verifies nothing,
//     and fails no parse either, but that id-RSASSA-PSS's parameters that parse as RSASSA-PSS-params
//     and write a field at its DEFAULT fail the parse, as the DEFAULTs above do in every carried
//     certificate, and parameters of any other form, such as a SEQUENCE with an INTEGER before such a
//     field, fail none;
//   - and the system clock reads before the end of 2035, after which NIST IR 8547 disallows ECDSA
//     and RSA alike.
//
// It refuses every other token timestamp-invalid, one that does not parse among them, and every token
// where roots is empty.
//
// evidenceRecord is the token's RFC 4998 EvidenceRecord, its renewal, and nil for none. Any other slice
// is a record given, one of zero bytes among them, which does not parse, so a record read from storage
// as empty is never taken for none. A record given with a token still in date is verified as given,
// and refused timestamp-invalid with the token where it does not verify, so a record that fails is
// never kept as if it held: it parses as Renewal reads RFC 4998, as DER, nested at most 64 deep, each
// token counted from its own ContentInfo, with no encryptionInfo, its cryptoInfos and each archive
// timestamp's attributes for their form alone, in any order, and every archive timestamp parsing as a
// token does; SHA-256 is its only hash, in one chain of archive timestamps, the first of which is
// token, byte for byte, covering head; each later one covers, through its reduced hash tree, the
// SHA-256 of the token before, and was taken before the end of 2035, that token's date; the last is
// accepted as Timestamps sets, under roots, by the clock, and each before it is read for its imprint
// and genTime alone. A token past its date verifies only through such a record whose last archive
// timestamp is in date, and no archive timestamp past 2035 is accepted until the format names a
// signature accepted past it, so such a token is refused whatever evidenceRecord holds.
//
// roots are the timestamp authorities' roots compiled into the release, each a DER X.509 certificate,
// never ones fetched or taken from the token, or the check proves nothing. A token proves that head
// existed at its time, and nothing of what head is the head of: the caller checks that it is the
// head of the trail it holds.
//
// A head that is not 32 bytes is a fault, and panics, and so is a root that does not keep the DER and
// X.509's ASN.1 a carried certificate keeps, every element in DER's form, no DEFAULT written out of
// those Timestamps lists and each extension RFC 5280 defines parsing as its schema, or holds its key in
// another form than an uncompressed ECDSA point on P-256 or P-384 under id-ecPublicKey or an RSA key
// under rsaEncryption with NULL parameters: a root is compiled into the release, so one that no chain
// could end at is the release's mistake, found before any token is checked under it.
func VerifyTimestamp(token, head []byte, roots [][]byte, evidenceRecord []byte) (VerifyTimestampResult, error) {
	if len(head) != sha256.Size {
		panic("verifyTimestamp: a head that is not 32 bytes")
	}
	parsed := make([]*chainCert, 0, len(roots))
	for _, r := range roots {
		c, err := timestamp.ParseCertificate(r)
		if err != nil {
			panic("verifyTimestamp: a root that is not a DER X.509 certificate, does not keep the DER or X.509's ASN.1 a carried certificate keeps, or whose extension does not parse as its schema")
		}
		root := chainCertificate(c)
		if root.key == nil {
			panic("verifyTimestamp: a root whose key is in another form than Timestamps accepts")
		}
		parsed = append(parsed, root)
	}
	if len(roots) == 0 {
		return VerifyTimestampResult{}, refusal.New(sealdcrypto.RefusalKindTimestampInvalid, "no root to verify a token under")
	}
	t, err := verifyTimestamp(token, head, parsed)
	if err != nil {
		return VerifyTimestampResult{}, err
	}
	// A nil record is none; any other is a record given, one of zero bytes among them, which does not
	// parse.
	if evidenceRecord != nil {
		if err := verifyEvidenceRecord(evidenceRecord, token, head, parsed); err != nil {
			return VerifyTimestampResult{}, err
		}
	}
	return VerifyTimestampResult{Time: t.at.Ceil()}, nil
}

// maxCertificates is the most certificates a token carries, of any form.
const maxCertificates = 8

const invalid = sealdcrypto.RefusalKindTimestampInvalid

// verifyTimestamp is der verified as a token over head under roots, as Timestamps sets, and its exact
// genTime.
func verifyTimestamp(der, head []byte, roots []*chainCert) (exactTime, error) {
	t, err := timestamp.Parse(der)
	if err != nil {
		return exactTime{}, refusal.New(invalid, "a token that does not parse")
	}
	info := t.Info
	switch {
	case t.Version != 3:
		return exactTime{}, refusal.New(invalid, "a SignedData of a version other than 3")
	case t.CertificateChoices > maxCertificates:
		return exactTime{}, refusal.New(invalid, "a token of more than eight certificates")
	case !t.EContentType.Equal(timestamp.OIDTSTInfo):
		return exactTime{}, refusal.New(invalid, "a token whose content is no TSTInfo")
	case info.Version != 1:
		return exactTime{}, refusal.New(invalid, "a TSTInfo of a version other than 1")
	case !info.HashAlgorithm.Algorithm.Equal(timestamp.OIDSHA256) || !absentOrNull(info.HashAlgorithm.Parameters):
		return exactTime{}, refusal.New(invalid, "an imprint that is not SHA-256")
	case !bytes.Equal(info.HashedMessage, head):
		return exactTime{}, refusal.New(invalid, "a token over another head")
	case slices.ContainsFunc(info.Extensions, func(e pkix.Extension) bool { return e.Critical }):
		return exactTime{}, refusal.New(invalid, "a TSTInfo with a critical extension")
	case len(t.SignerInfos) != 1:
		return exactTime{}, refusal.New(invalid, "a token of other than one signer info")
	}
	s := t.SignerInfos[0]

	switch {
	case !versionNamesSigner(s):
		return exactTime{}, refusal.New(invalid, "a signer info of a version other than its signer's name gives")
	case len(s.ContentType) != 1 || len(s.MessageDigest) != 1 || len(s.SigningCertificateV2) != 1:
		return exactTime{}, refusal.New(invalid, "a signed attribute missing or given twice")
	case !s.ContentType[0].Equal(timestamp.OIDTSTInfo):
		return exactTime{}, refusal.New(invalid, "a contentType attribute that is not TSTInfo")
	}
	digest, ok := hashOf(s.DigestAlgorithm)
	if !ok {
		return exactTime{}, refusal.New(invalid, "a digest algorithm other than SHA-256, SHA-384 or SHA-512")
	}
	if !bytes.Equal(hashed(digest, t.EContent), s.MessageDigest[0]) {
		return exactTime{}, refusal.New(invalid, "a messageDigest that is not the TSTInfo's")
	}

	certs := make([]*chainCert, 0, len(t.Certificates))
	for _, raw := range t.Certificates {
		// A key in another form verifies nothing: its certificate gives the chain nothing, and fails no
		// parse for it.
		if c := chainCertificate(raw); c.key != nil {
			certs = append(certs, c)
		}
	}
	i := slices.IndexFunc(certs, func(c *chainCert) bool { return names(s, c) })
	if i < 0 {
		return exactTime{}, refusal.New(invalid, "a signer whose certificate the token does not carry")
	}
	signer := certs[i]

	if err := signatureVerifies(s, digest, signer); err != nil {
		return exactTime{}, err
	}
	if !bound(s.SigningCertificateV2[0], signer) {
		return exactTime{}, refusal.New(invalid, "a signingCertificateV2 that does not bind the signer's certificate")
	}

	if !slices.Contains(signer.ExtKeyUsage(), oidTimeStamping) {
		return exactTime{}, refusal.New(invalid, "a signer's certificate without the time-stamping usage")
	}
	at := exactly(info)
	if !chains(signer, certs, roots, at) {
		return exactTime{}, refusal.New(invalid, "a signer's certificate that chains to no root given, as Timestamps checks a chain")
	}

	if !now().Before(signatureDate) {
		return exactTime{}, refusal.New(invalid, "a token past its signature's date")
	}
	return at, nil
}

// exactTime is a genTime as the chain is checked at it, exactly, its fraction kept whole however fine.
type exactTime struct{ at timestamp.Instant }

func exactly(info timestamp.Info) exactTime { return exactTime{info.GenTime} }

// within is whether the time is in c's window, its start and end included (RFC 5280, 4.1.2.5), each
// compared exactly, a window's fraction of a second among it.
func (t exactTime) within(c *chainCert) bool {
	return c.NotBefore.Compare(t.at) <= 0 && t.at.Compare(c.NotAfter) <= 0
}

// versionNamesSigner is whether the signer info's version is the one the name of its signer gives:
// version 1 by issuer and serial number, version 3 by subject key identifier (RFC 5652, 5.3).
func versionNamesSigner(s timestamp.SignerInfo) bool {
	return s.Version == 1 && s.Serial != nil || s.Version == 3 && s.Serial == nil
}

// signatureVerifies checks the signer info's signature over its signed attributes, under the
// algorithms a token's signature may be.
func signatureVerifies(s timestamp.SignerInfo, digest crypto.Hash, signer *chainCert) error {
	a := s.SignatureAlgorithm
	h := hashed(digest, s.SignedAttributes)
	switch {
	case a.Algorithm.Equal(oidECDSAWithSHA256), a.Algorithm.Equal(oidECDSAWithSHA384), a.Algorithm.Equal(oidECDSAWithSHA512):
		pub, ok := signer.key.(*ecdsa.PublicKey)
		switch {
		case len(a.Parameters.FullBytes) > 0 || ecdsaHashes[a.Algorithm.String()] != digest:
			return refusal.New(invalid, "a signature algorithm whose hash is not the digest algorithm's")
		case !ok || (pub.Curve != elliptic.P256() && pub.Curve != elliptic.P384()):
			return refusal.New(invalid, "a token's signer whose key is not ECDSA on P-256 or P-384")
		case !ecdsa.VerifyASN1(pub, h, s.Signature):
			return refusal.New(invalid, "a token's signature that does not verify")
		}
		return nil
	case a.Algorithm.Equal(oidRSAEncryption), a.Algorithm.Equal(oidSHA256WithRSA), a.Algorithm.Equal(oidSHA384WithRSA), a.Algorithm.Equal(oidSHA512WithRSA):
		if !absentOrNull(a.Parameters) || (!a.Algorithm.Equal(oidRSAEncryption) && rsaHashes[a.Algorithm.String()] != digest) {
			return refusal.New(invalid, "a signature algorithm whose hash is not the digest algorithm's")
		}
		pub, err := rsaSigner(signer)
		if err != nil {
			return err
		}
		if rsa.VerifyPKCS1v15(pub, digest, h, s.Signature) != nil {
			return refusal.New(invalid, "a token's signature that does not verify")
		}
		return nil
	case a.Algorithm.Equal(oidRSASSAPSS):
		p, err := timestamp.ParsePSS(a.Parameters)
		if err != nil {
			return refusal.New(invalid, "RSASSA-PSS parameters that do not parse")
		}
		if ph, ok := hashOf(pkix.AlgorithmIdentifier{Algorithm: p.Hash}); !ok || ph != digest || !p.MGF.Equal(timestamp.OIDMGF1) ||
			!p.MGFHash.Equal(p.Hash) || p.TrailerField != 1 {
			return refusal.New(invalid, "RSASSA-PSS parameters that do not name the digest algorithm's hash")
		}
		// Each hash identifier's parameters are absent or NULL, as RFC 4055, 2.1, has them.
		if !absentOrNull(p.HashParameters) || !absentOrNull(p.MGFHashParameters) {
			return refusal.New(invalid, "RSASSA-PSS parameters whose hash identifier's parameters are neither absent nor NULL")
		}
		// A salt of the hash's length, as RFC 4055, 3.1, recommends, and no other.
		if p.SaltLength != digest.Size() {
			return refusal.New(invalid, "RSASSA-PSS parameters whose salt is not the hash's length")
		}
		pub, err := rsaSigner(signer)
		if err != nil {
			return err
		}
		if rsa.VerifyPSS(pub, digest, h, s.Signature, &rsa.PSSOptions{SaltLength: p.SaltLength}) != nil {
			return refusal.New(invalid, "a token's signature that does not verify")
		}
		return nil
	}
	return refusal.New(invalid, "a token's signature under an algorithm Timestamps does not accept")
}

// minTokenRSABits is the least RSA key a token's signature is accepted under, since IR 8547
// deprecates RSA of 2048 bits after 2030, before signatureDate.
const minTokenRSABits = 3072

func rsaSigner(signer *chainCert) (*rsa.PublicKey, error) {
	pub, ok := signer.key.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < minTokenRSABits {
		return nil, refusal.New(invalid, "a token's signer whose key is not RSA of 3072 bits or more")
	}
	return pub, nil
}

// names is whether the signer info names c as its signer.
func names(s timestamp.SignerInfo, c *chainCert) bool {
	if s.Serial == nil {
		id := c.SubjectKeyID()
		return len(id) > 0 && bytes.Equal(s.SubjectKeyID, id)
	}
	return bytes.Equal(s.Issuer, c.Issuer) && s.Serial.Cmp(c.Serial) == 0
}

// bound is whether sc's first ESSCertIDv2 binds c: its hash, and its issuer and serial number where it
// names them (RFC 5035, 5.4).
func bound(sc timestamp.SigningCertificateV2, c *chainCert) bool {
	if len(sc.Certs) == 0 {
		return false
	}
	id := sc.Certs[0]
	h, ok := hashOf(id.HashAlgorithm)
	if !ok || !bytes.Equal(hashed(h, c.Raw), id.CertHash) {
		return false
	}
	is := id.IssuerSerial
	return is == nil || (is.Names == 1 && len(is.DirectoryNames) == 1 &&
		bytes.Equal(is.DirectoryNames[0], c.Issuer) && is.Serial.Cmp(c.Serial) == 0)
}

// maxChain is the most certificates a chain holds, the signer's and the root among them, and
// maxSignatureChecks the most signatures a search for a chain checks, as crypto/x509 bounds its own,
// so a token of many certificates under one name refuses in bounded time.
const (
	maxChain           = 8
	maxSignatureChecks = 100
)

// chains is whether signer chains to one of roots through certs, the token's, at genTime, as
// VerifyTimestamp checks a chain: RFC 5280's path validation (6.1) without revocation, policies or
// name constraints. crypto/x509's Verify checks name constraints and the extended key usage of
// every certificate, and not a critical nameConstraints or certificatePolicies, so each check is made
// here, and crypto/x509 checks each link's signature alone. The root's own signature is not checked.
func chains(signer *chainCert, certs, roots []*chainCert, genTime exactTime) bool {
	type link struct{ child, issuer *chainCert }
	checked, budget := map[link]bool{}, maxSignatureChecks
	signs := func(issuer, c *chainCert) bool {
		l := link{c, issuer}
		if ok, done := checked[l]; done {
			return ok
		}
		if budget == 0 {
			return false
		}
		budget--
		checked[l] = c.Signature != nil &&
			(&x509.Certificate{PublicKey: issuer.key}).CheckSignature(c.algorithm, c.TBS, c.Signature) == nil
		return checked[l]
	}
	isRoot := func(c *chainCert) bool {
		return slices.ContainsFunc(roots, func(r *chainCert) bool { return bytes.Equal(r.Raw, c.Raw) })
	}

	var build func(chain []*chainCert) bool
	build = func(chain []*chainCert) bool {
		for _, r := range roots {
			if links(chain, r, genTime) && signs(r, chain[len(chain)-1]) {
				return true
			}
		}
		if len(chain) >= maxChain-1 {
			return false
		}
		for _, c := range certs {
			if !slices.Contains(chain, c) && !isRoot(c) && links(chain, c, genTime) && signs(c, chain[len(chain)-1]) &&
				build(append(slices.Clip(chain), c)) {
				return true
			}
		}
		return false
	}
	return accepted(signer, genTime) && build([]*chainCert{signer})
}

// links is whether issuer may sign the last certificate of chain, as VerifyTimestamp checks a link,
// but for the signature itself: its subject byte for byte the certificate's issuer, the certificate
// signed over SHA-256 or longer, and issuer a CA whose key usage, where it has one, signs
// certificates, whose path length constraint, where it has one, the chain below it keeps, and which
// is itself accepted. A key usage of no bit set is one all the same, and signs no certificate.
func links(chain []*chainCert, issuer *chainCert, genTime exactTime) bool {
	c := chain[len(chain)-1]
	basic, ca, pathLen := issuer.BasicConstraints()
	usage, hasUsage := issuer.KeyUsage()
	if !bytes.Equal(issuer.Subject, c.Issuer) || !accepted(issuer, genTime) || !basic || !ca ||
		(hasUsage && !keyCertSign(usage)) || !slices.Contains(chainSignatures, c.algorithm) {
		return false
	}
	// pathLenConstraint bounds the certificates between issuer and the signer's that are not
	// self-issued (RFC 5280, 4.2.1.9 and 6.1.4), -1 where it gives none.
	below := 0
	for _, b := range chain[1:] {
		if !bytes.Equal(b.Subject, b.Issuer) {
			below++
		}
	}
	return pathLen < 0 || below <= pathLen
}

// keyCertSign is whether bits, a keyUsage's, set keyCertSign, bit 5.
func keyCertSign(bits []byte) bool { return len(bits) > 0 && bits[0]&(0x80>>5) != 0 }

// accepted is whether c may stand in a chain: valid at genTime, its key ECDSA on P-256 or P-384 or RSA
// of 2048 bits or more, each in its one form, and no critical extension but basicConstraints, keyUsage
// and extendedKeyUsage.
func accepted(c *chainCert, genTime exactTime) bool {
	if !genTime.within(c) {
		return false
	}
	switch pub := c.key.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() && pub.Curve != elliptic.P384() {
			return false
		}
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			return false
		}
	default:
		return false
	}
	return !slices.ContainsFunc(c.Extensions, func(e timestamp.Extension) bool {
		return e.Critical && e.ID != oidBasicConstraints && e.ID != oidKeyUsage && e.ID != oidExtKeyUsage
	})
}

// chainCert is a certificate as the chain reads it: c, its key, nil where it is in another form than
// Timestamps accepts and so verifies nothing, and the algorithm its issuer signed it under, as
// crypto/x509 names it, x509.UnknownSignatureAlgorithm for any other.
type chainCert struct {
	*timestamp.Certificate
	key       crypto.PublicKey
	algorithm x509.SignatureAlgorithm
}

// chainCertificate is c, which internal/timestamp has held to the DER, the ASN.1 and the schemas
// Timestamps sets, as the chain reads it. crypto/x509 reads its key alone, once it is in the form
// Timestamps accepts, and verifies each link's signature, so nothing X.509's ASN.1 accepts fails a
// parse for what crypto/x509 refuses.
func chainCertificate(c *timestamp.Certificate) *chainCert {
	out := &chainCert{Certificate: c, algorithm: signatureAlgorithm(c.SignatureAlgorithm)}
	if keyInItsForm(c.SubjectPublicKeyInfo) {
		if key, err := x509.ParsePKIXPublicKey(c.SubjectPublicKeyInfo); err == nil {
			out.key = key
		}
	}
	return out
}

// signatureAlgorithm is the algorithm a, the DER of a certificate's signatureAlgorithm, names, as
// crypto/x509 names it: ECDSA over SHA-256, SHA-384 or SHA-512, its parameters absent (RFC 5758, 3.2);
// RSA under PKCS #1 v1.5 over one of those hashes, its parameters absent or NULL (RFC 4055, 5); or RSA
// under id-RSASSA-PSS, whose parameters name one of those hashes for the signature and for MGF1 alike,
// each hash identifier's parameters absent or NULL, a salt of its length and trailerField 1. Any other,
// one of those object identifiers with other parameters among them, is x509.UnknownSignatureAlgorithm,
// under which nothing verifies: crypto/x509 reads the object identifier alone, so the parameters are
// checked here, and a certificate signed under other parameters still parses.
func signatureAlgorithm(a []byte) x509.SignatureAlgorithm {
	var ai struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(a, &ai); err != nil {
		return x509.UnknownSignatureAlgorithm
	}
	id := ai.Algorithm.String()
	switch {
	case ecdsaHashes[id] != 0:
		if len(ai.Parameters.FullBytes) > 0 {
			return x509.UnknownSignatureAlgorithm
		}
		return signatureAlgorithms[id]
	case rsaHashes[id] != 0:
		if !absentOrNull(ai.Parameters) {
			return x509.UnknownSignatureAlgorithm
		}
		return signatureAlgorithms[id]
	case !ai.Algorithm.Equal(oidRSASSAPSS):
		return x509.UnknownSignatureAlgorithm
	}
	p, err := timestamp.ParsePSS(ai.Parameters)
	if err != nil {
		return x509.UnknownSignatureAlgorithm
	}
	h, ok := hashOf(pkix.AlgorithmIdentifier{Algorithm: p.Hash})
	if !ok || !p.MGF.Equal(timestamp.OIDMGF1) || !p.MGFHash.Equal(p.Hash) || p.TrailerField != 1 || p.SaltLength != h.Size() ||
		!absentOrNull(p.HashParameters) || !absentOrNull(p.MGFHashParameters) {
		return x509.UnknownSignatureAlgorithm
	}
	return map[crypto.Hash]x509.SignatureAlgorithm{
		crypto.SHA256: x509.SHA256WithRSAPSS, crypto.SHA384: x509.SHA384WithRSAPSS, crypto.SHA512: x509.SHA512WithRSAPSS,
	}[h]
}

// signatureAlgorithms is each algorithm a certificate is signed under that its object identifier names,
// as crypto/x509 reads it, whose parameters signatureAlgorithm checks.
var signatureAlgorithms = map[string]x509.SignatureAlgorithm{
	oidECDSAWithSHA256.String(): x509.ECDSAWithSHA256,
	oidECDSAWithSHA384.String(): x509.ECDSAWithSHA384,
	oidECDSAWithSHA512.String(): x509.ECDSAWithSHA512,
	oidSHA256WithRSA.String():   x509.SHA256WithRSA,
	oidSHA384WithRSA.String():   x509.SHA384WithRSA,
	oidSHA512WithRSA.String():   x509.SHA512WithRSA,
}

// keyInItsForm is whether spki, a certificate's subjectPublicKeyInfo, is a key in the one form
// Timestamps accepts: an ECDSA point, uncompressed, under id-ecPublicKey naming its curve, P-256 or
// P-384, or an RSA key under rsaEncryption with NULL parameters. A key in any other form verifies
// nothing, whatever crypto/x509 reads of it: a carried certificate holding one gives the chain nothing,
// and a root holding one is a fault. Which sizes an RSA key is accepted at is accepted's and the
// signature's to check: this is the key's form alone.
func keyInItsForm(spki []byte) bool {
	// encoding/asn1 skips what follows a struct's fields, so each struct ends in After, which takes the
	// first element left: a key whose structure holds one more is in another form. An
	// AlgorithmIdentifier is so held to at most two parts.
	var info struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
			After      asn1.RawValue `asn1:"optional"`
		}
		Key   asn1.BitString
		After asn1.RawValue `asn1:"optional"`
	}
	if rest, err := asn1.Unmarshal(spki, &info); err != nil || len(rest) > 0 ||
		len(info.Algorithm.After.FullBytes) > 0 || len(info.After.FullBytes) > 0 {
		return false
	}
	p, key := info.Algorithm.Parameters, info.Key
	if key.BitLength != 8*len(key.Bytes) {
		return false
	}
	switch {
	case info.Algorithm.Algorithm.Equal(oidRSAEncryption):
		// An RSA key: RFC 8017's RSAPublicKey, its modulus and its public exponent each positive, as
		// crypto/rsa holds one.
		var k struct {
			N, E  *big.Int
			After asn1.RawValue `asn1:"optional"`
		}
		if rest, err := asn1.Unmarshal(key.Bytes, &k); err != nil || len(rest) > 0 || len(k.After.FullBytes) > 0 {
			return false
		}
		return bytes.Equal(p.FullBytes, asn1.NullBytes) && k.N.Sign() > 0 && k.E.Sign() > 0 && k.E.IsInt64() && k.E.Int64() <= math.MaxInt
	case info.Algorithm.Algorithm.Equal(oidECPublicKey):
		var curve asn1.ObjectIdentifier
		if rest, err := asn1.Unmarshal(p.FullBytes, &curve); err != nil || len(rest) > 0 {
			return false
		}
		c, ok := curves[curve.String()]
		if !ok {
			return false
		}
		// An ECDSA point, uncompressed and on its curve.
		_, err := ecdsa.ParseUncompressedPublicKey(c, key.Bytes)
		return err == nil
	}
	return false
}

// curves is each curve Timestamps accepts a point on, by its name.
var curves = map[string]elliptic.Curve{
	oidP256.String(): elliptic.P256(),
	oidP384.String(): elliptic.P384(),
}

var chainSignatures = []x509.SignatureAlgorithm{
	x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
	x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
	x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
}

var (
	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidRSASSAPSS       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidECPublicKey     = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidP256            = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384            = asn1.ObjectIdentifier{1, 3, 132, 0, 34}

	oidBasicConstraints = timestamp.NewOID(asn1.ObjectIdentifier{2, 5, 29, 19})
	oidKeyUsage         = timestamp.NewOID(asn1.ObjectIdentifier{2, 5, 29, 15})
	oidExtKeyUsage      = timestamp.NewOID(asn1.ObjectIdentifier{2, 5, 29, 37})
	oidTimeStamping     = timestamp.NewOID(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8})

	hashes = map[string]crypto.Hash{
		oidSHA256.String(): crypto.SHA256, oidSHA384.String(): crypto.SHA384, oidSHA512.String(): crypto.SHA512,
	}
	ecdsaHashes = map[string]crypto.Hash{
		oidECDSAWithSHA256.String(): crypto.SHA256, oidECDSAWithSHA384.String(): crypto.SHA384, oidECDSAWithSHA512.String(): crypto.SHA512,
	}
	rsaHashes = map[string]crypto.Hash{
		oidSHA256WithRSA.String(): crypto.SHA256, oidSHA384WithRSA.String(): crypto.SHA384, oidSHA512WithRSA.String(): crypto.SHA512,
	}
)

// hashOf is the hash a, a hash's algorithm identifier, names, where it is SHA-256, SHA-384 or SHA-512
// and its parameters absent or NULL, as RFC 5754 allows both.
func hashOf(a pkix.AlgorithmIdentifier) (crypto.Hash, bool) {
	h, ok := hashes[a.Algorithm.String()]
	return h, ok && absentOrNull(a.Parameters)
}

func absentOrNull(p asn1.RawValue) bool {
	return len(p.FullBytes) == 0 || bytes.Equal(p.FullBytes, asn1.NullBytes)
}

func hashed(h crypto.Hash, b []byte) []byte {
	w := h.New()
	w.Write(b)
	return w.Sum(nil)
}

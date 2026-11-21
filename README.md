# Seald Healthcare Crypto for Go

Seald's cryptography library for Go, an implementation of the Crypto API. It signs and verifies, wraps keys to devices, seals and opens encrypted records and files, writes a backup key as a recovery phrase and checks timestamp tokens, with hybrid post-quantum keys throughout and no dependency outside Go's standard library. The public API conventions are in [docs/rendering.md](docs/rendering.md).

Its bytes are the Crypto API's, and every implementation of the Crypto API reproduces the same test vectors, so what one writes, another reads.

## Overview

The library is four packages, split by what each is able to do, so a service imports only what it needs, and a fifth, the seal of a service that wraps one purpose alone. A service that only checks signatures imports `verify` alone. A service that must never decrypt leaves out `open`, and no other package links the code that decrypts. A service that wraps a re-founding's challenge and nothing else imports `seal/refoundingchallenge` in place of `seal`.

| Package                        | Offers                                                                                                                                     |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `sealdcrypto`, the module root | The words every package shares: `Refusal` and its kinds, `UUID` with `ParseUUID`, `TenantID`, `RecipientID`, `Locator`, `JSON`, `Person`, `Algorithm`, `PublicKey`, `Label`, `WrapContext`, and `Contract`, the version of the Crypto API implemented. No private key |
| [`verify`](verify/doc.go)      | Canonical JSON and tuples, a setup code's or a guest code's text, hashes, the tokenisation check, the unlock challenge, the App Attest challenge and the passkey challenge, public keys and their fingerprint words; verifying signatures, certificates, cards, kept signatures' cards and timestamp tokens; reading each signed body; checking a whole container against its envelope with no key |
| [`sign`](sign/doc.go)          | Generating a signing key, importing one from its seed, deriving an identity authority, signing under a label, certifying a body, and zeroising a signing key |
| [`seal`](seal/doc.go)          | Wrapping a secret to a public key                                                                                                          |
| [`seal/refoundingchallenge`](seal/refoundingchallenge/refoundingchallenge.go) | Wrapping a re-founding's challenge to the backup key, purpose `refounding-challenge`, and no other secret |
| [`open`](open/doc.go)          | Generating device and receiving keys, importing and exporting a private key, unwrapping a secret, or a domain key under its epoch's key digest, under a key it holds or under one held elsewhere, decapsulating, sealing and opening containers, a folder index and a pre-image journal among them, derivations, the backup key's recovery phrase, randomness, and zeroising a secret |

Each operation is named for the vectors' operation it reproduces, in Go's case: `importPublicKey` is `verify.ImportPublicKey`. [docs/rendering.md](docs/rendering.md) maps every operation, and every concept of the Crypto API, to its Go form. `sealdcrypto.Contract` names the version of the Crypto API the library implements, `v1`.

## Cryptography

### Primitives

Every primitive is Go's standard library's. This library composes them, and implements none.

| Used for                                 | Primitive                                                       | Standard                                             | Go package                                                                             | Audited                                                 |
| ---------------------------------------- | --------------------------------------------------------------- | ---------------------------------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| Hashes, key digests, commitments, a recovery phrase's checksum | SHA-256, HMAC-SHA-256, HKDF-SHA-256                             | FIPS 180-4, RFC 2104, RFC 5869                       | `crypto/sha256`, `crypto/hmac`, `crypto/hkdf`                                          | Yes                                                     |
| Content, wraps                           | AES-256-GCM                                                     | SP 800-38D                                           | `crypto/aes`, `crypto/cipher`                                                          | Yes                                                     |
| Wraps                                    | HPKE base mode with X-Wing, ML-KEM-768 and X25519, KEM `0x647A` | RFC 9180, draft-connolly-cfrg-xwing-kem-11, FIPS 203 | `crypto/hpke`'s `MLKEM768X25519`, over `crypto/mlkem`, `crypto/ecdh` and `crypto/sha3`; and for a key held elsewhere, `crypto/hkdf`, `crypto/aes` and `crypto/cipher`, and for its holder `crypto/mlkem`, `crypto/ecdh` and `crypto/sha3` themselves | ML-KEM, X25519, SHA-3, HKDF and AES-GCM yes; `crypto/hpke` no |
| Signatures, certificates                 | Ed25519 and ML-DSA-65, both over every message                  | RFC 8032, FIPS 204                                   | `crypto/ed25519`, `crypto/mldsa`                                                       | Ed25519 yes; ML-DSA no                                  |
| Canonical JSON                           | JCS                                                             | RFC 8785                                             | `encoding/json/jsontext`                                                               | No                                                      |
| Timestamp tokens                         | ECDSA on P-256 and P-384, RSA under PKCS #1 v1.5 and PSS, X.509, SHA-384 and SHA-512 | RFC 3161, RFC 5652, RFC 5280, FIPS 180-4 | `crypto/ecdsa`, `crypto/rsa`, `crypto/x509`, `encoding/asn1`, `crypto/sha512` | ECDSA, RSA and SHA-2 yes; `crypto/x509` and `encoding/asn1` no |
| Every key, seed, nonce and secret        | The CSPRNG                                                      |                                                      | `crypto/rand`                                                                          | Yes                                                     |

The audit is [Trail of Bits' of May 2025](https://go.dev/blog/tob-crypto-audit), over the packages of Go's FIPS 140-3 module.

What this library builds on them is no primitive, and each is held to its own vectors or to a reference computed apart:

| Built here                    | How                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Ed25519's checks at import    | [`internal/keyimport/ed25519.go`](internal/keyimport/ed25519.go): the canonical encoding and the 8 points of small order as byte comparisons over public constants, and whether a point is on the curve as `crypto/ed25519` decodes it, read from `VerifyWithOptions`' error so that another wording refuses every key. The tests hold the constants to the curve in `math/big`                                                                                                                           |
| HPKE's key schedule from a shared secret | [`internal/unwrap`](internal/unwrap/unwrap.go): RFC 9180's base-mode `KeyScheduleR` and single-shot `Open`, for a wrap opened with the shared secret a key held elsewhere decapsulates to, which `crypto/hpke` takes no way in: `LabeledExtract` and `LabeledExpand` over `crypto/hkdf` with SHA-256, the suite's `suite_id`, and AES-256-GCM from `crypto/aes` and `crypto/cipher` under `base_nonce`, sequence number 0. The tests hold its key and `base_nonce` to RFC 9180's base-mode vectors under HKDF-SHA256 and AES-256-GCM, every KEM's, and its open to each one's first encryption, and every wrap of the vectors to the secret or the refusal `crypto/hpke` opens it to |
| X-Wing's decapsulation to its shared secret | [`internal/xwing`](internal/xwing/xwing.go) and [`internal/unwrap`](internal/unwrap/unwrap.go): draft-connolly-cfrg-xwing-kem-11's seed expansion, SHAKE256 to 96 bytes, and its combiner, SHA3-256 over ML-KEM-768's and X25519's shared secrets, the ephemeral, the key's X25519 public value and the label, over `crypto/sha3`, with ML-KEM-768's decapsulation from `crypto/mlkem` and X25519 from `crypto/ecdh`, for a key's `Decapsulate`, since `crypto/hpke` gives no shared secret out. An all-zero X25519 shared secret, an ephemeral of small order, is refused. The tests hold it to the draft's three vectors, each key's halves to the public value `crypto/hpke` derives, and each wrap it opens to `crypto/hpke`'s |
| X25519's checks at import     | [`internal/keyimport/x25519.go`](internal/keyimport/x25519.go): the canonical encoding of a u-coordinate as a byte comparison with p, bit 255 clear, and a point of small order where `crypto/ecdh` refuses its all-zero product with a fixed scalar. The tests hold the scalar to no multiple of the curve's or the twist's large prime order, the check to every encoding of a point of small order, and the encoding to every value from p to 2^255 − 1 in `math/big`                                    |
| BIP-39's English words        | [`internal/bip39`](internal/bip39/LICENSE): bitcoin/bips' `english.txt` at `ce1862a` under MIT, held to its SHA-256 and to BIP-39's vectors. A recovery phrase is written and read through it with every word of the list read, and every place of the text, under masks, so no branch or index follows the seed                                                                                                                                                                                                                                                                                                                                       |
| RFC 3161 tokens and their CMS | [`internal/timestamp`](internal/timestamp/timestamp.go): a DER reader of only the parts a check needs, each with nothing after its elements, over `encoding/asn1` for the token's CMS and the TSTInfo, and a genTime's fraction of a second kept whole. A walk of every element ([`der.go`](internal/timestamp/der.go)), read or not, holds the token, and an evidence record, to DER's rules that need no schema: lengths, string forms, integers, object identifiers of any size, booleans, a BIT STRING's padding, time forms, each SET's order and a nesting of 64; and its TSTInfo, signed attributes, signer info and certificates, and each root, to the DEFAULTs the format lists as never written out. Each certificate it carries, and each root, is read here as X.509's ASN.1 sets it ([`certificate.go`](internal/timestamp/certificate.go)), and each extension RFC 5280 defines as RFC 5280's ASN.1 modules set it ([`schema.go`](internal/timestamp/schema.go)), so are the signed attributes' names and policies: `crypto/x509` parses only part of those modules, and refuses some of what X.509's ASN.1 allows, such as a version above v3 or a negative serial. So `crypto/x509` reads a certificate's key alone, once it is in its form, and checks each link's signature by `CheckSignature`, under a signature algorithm whose parameters are checked here, since `crypto/x509` reads its object identifier alone. The chain is built and checked here as RFC 5280's path validation without revocation, policies or name constraints, which `crypto/x509`'s `Verify` would check, each window compared with the genTime exactly. An RFC 4998 evidence record is read here ([`evidence.go`](internal/timestamp/evidence.go)), and its reduced hash trees computed in `verify`. Fuzzed, and held to public authorities' tokens, each of whose certificates reads here as `crypto/x509` reads it |

### Security properties

- **Hybrid post-quantum.** Every wrap is to X-Wing, which holds while either ML-KEM-768 or X25519 does. Every signature is Ed25519 and ML-DSA-65 over the same message, and verifies only where both halves do.
- **Domain separation.** A signature is made under a label, such as `sealdcrypto.LabelEnvelope`, and verifies under no other. A wrap is bound to its purpose and the identifiers of what it is for, so one never opens as another.
- **Committed content.** A container's content is AES-256-GCM in frames of 64 KiB, each checked against its segment's list of frames, whose root the signed envelope carries, with a commitment to the key per segment. A range is read and checked without reading the rest.
- **Bodies read as laid out.** Every signed body, a certificate's and a backup key's registration among them, is read from the very bytes signed, as canonical JSON holding exactly the members the format names, each in its one form, a registration's fingerprint its key's digest, and refused otherwise, so no caller acts on a member nobody signed. `verify` has a reader for each body, `verify.ReadInvitationBody` among them, and the caller picks the one for the body it expects. Making a certificate checks its body as a reader does, so no certificate is made that a reader refuses.
- **Checked keys.** A public key is made only by `verify.ImportPublicKey`, which refuses an X25519 or Ed25519 point of small order, an X25519 or Ed25519 encoding that is not canonical and an ML-KEM key that fails FIPS 203's check, or by a private key's `PublicKey()`. No operation takes a key that was never checked.
- **Private keys stay in their handle.** `sign.SigningKey`, `open.ReceivingKey` and `open.DeviceKey` have no field, print only their algorithm and recipient id under every format verb, and give up their private half only through `open.ExportPrivateKey`. A signing key signs only a message under a label. A receiving key or a device key decapsulates a wrap's encapsulation to X-Wing's shared secret, which opens that wrap alone, for the library that opens it apart from the key.
- **Keys held elsewhere.** `sign.Sign` and `sign.Certify` take any `sign.Signer`, and `open.UnwrapWith` any `open.Receiver`, so a key a hardware key store holds signs and receives without leaving it. What a signer returns is verified under its key before it is used. A receiver is asked only once a wrap passes every check that reads no secret, its length of 1168 bytes and its ephemeral among them, and a shared secret that does not open the wrap under the context the caller asks for is refused as any wrap that does not open is. Either one's own error is returned unchanged. Each handle's `Zeroise` wipes it, `sign.SigningKey`'s in `sign` itself, so a service that links `sign` without `open` wipes the key it holds. Such a service also loads a signing key from its seed with `sign.ImportSigningKey`, and derives each tenant's identity authority from one authority seed with `sign.IdentityAuthority`.
- **Secrets.** No branch or table index depends on a secret: a recovery phrase's words are looked up, compared and placed in its text through `crypto/subtle`, and its seed is used only once its key's digest is the fingerprint the caller pinned. Every secret an operation returns is the caller's to zeroise with `open.Zeroise`. Go's garbage collector may copy memory, so zeroising narrows a secret's lifetime and does not end it.
- **Randomness** comes from `crypto/rand` alone.
- **Refusals and faults.** Bytes from a wire or from storage that fail are refused, as a `*sealdcrypto.Refusal` whose detail never quotes the input, so a refusal may be logged whole. A caller's own mistake, such as a zero key or a head of the wrong size, is a fault, and panics. Bytes from a wire or from storage never panic, which a fuzz test of each parser checks: every secret is 32 bytes, so every wrap is 1168 bytes, and `open.Unwrap` refuses a wrap of another length before it decrypts it, so what it returns is always a secret of 32 bytes. On a 32-bit platform, `Content` asked for a content or range longer than a slice holds also panics, which `ContentLength` lets a caller check first.
- **Interoperable.** Every operation reproduces the test vectors every implementation of the Crypto API writes and reproduces, and each standard's own.

## Installation

Go 1.27.2 or later. Install a released version:

```sh
go get github.com/seald-healthcare/crypto-go@latest
```

Pin an exact published version in your `go.mod`. Releases use tags of the form `vX.Y.Z`. Before `v1.0.0`, a minor version may change the API.

## Quickstart

A device signs an envelope under the `envelope` label, and a reader verifies the signature under the device's key as it stored it:

```go
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/open"
	"github.com/seald-healthcare/crypto-go/sign"
	"github.com/seald-healthcare/crypto-go/verify"
)

func main() {
	ctx := context.Background()
	device := open.GenerateDeviceKey()

	// The writer signs the envelope's canonical JSON, cut short here.
	writer := verify.RecipientID(device.PublicKey())
	payload, err := verify.CanonicalJSON(map[string]any{
		"locator": "file-1",
		"version": 3,
		"epoch":   1,
		"writer":  base64.RawURLEncoding.EncodeToString(writer[:]),
	})
	if err != nil {
		log.Fatal(err)
	}
	label := sealdcrypto.LabelEnvelope
	signature, err := sign.Sign(ctx, device, label, payload)
	if err != nil {
		log.Fatal(err)
	}

	// The reader imports the key from its stored algorithm and value.
	stored := device.PublicKey()
	key, err := verify.ImportPublicKey(stored.Algorithm(), stored.Value())
	if err != nil {
		log.Fatal(err)
	}
	ok, err := verify.VerifySignature(key, label, payload, signature)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ok)

	// Under another label, the same signature verifies nothing.
	other := sealdcrypto.LabelCommit
	fmt.Println(verify.VerifySignature(key, other, payload, signature))

	// Under a label v1 does not have, it is refused, and gives no verdict.
	_, err = verify.VerifySignature(key, "web-release", payload, signature)
	fmt.Println(err)
}
```

It prints `true`, then `false <nil>`: a signature verifies under its own label alone. Under a label v1 does not have, it prints `sealdcrypto: unsupported: a label v1 does not have`: such a label is refused before the key or the signature is looked at, so it is told apart from a signature that does not verify.

## Common use cases

In the snippets below, `b64` writes bytes as JSON holds them: base64url without padding.

### Handle a refusal

An operation given bytes from a wire or from storage that fail returns a `*sealdcrypto.Refusal`. Decide on its kind, and treat a kind you do not know as a refusal still. Any other error is not about the bytes: a key store's, the network's or `io`'s own.

```go
// status is the HTTP status of an operation's error.
func status(err error) int {
	var refusal *sealdcrypto.Refusal
	switch {
	case err == nil:
		return http.StatusOK
	case errors.As(err, &refusal):
		// A refusal never quotes its input, so it is logged whole.
		log.Printf("refused: %v", refusal)
		if refusal.Kind == sealdcrypto.RefusalKindMalformed {
			return http.StatusBadRequest
		}
		// Every other kind, and any kind added later, is refused too.
		return http.StatusUnprocessableEntity
	default:
		// Not a refusal: the key store's, the network's or io's error.
		return http.StatusInternalServerError
	}
}
```

### Seal a file for its recipients

`open.SealContainer` streams the encrypted container under a fresh content key, and returns each segment's commitments for the envelope the writer signs. `seal.Wrap` wraps the content key to each recipient's device, bound to the version and segment it is for:

```go
// sealedFile is what writing a version of a file gives: the container
// for storage, the commitments for the signed envelope, and the content
// key wrapped to each recipient.
type sealedFile struct {
	container   []byte
	commitments []open.SegmentCommitment
	wrapped     [][]byte
}

// sealFile seals a file's content as version 1 of file-1, and wraps its
// key to each recipient's device.
func sealFile(
	tenant sealdcrypto.TenantID,
	recipients []sealdcrypto.PublicKey,
	content []byte,
) (sealedFile, error) {
	key := open.NewContentKey()
	defer open.Zeroise(key)

	var container bytes.Buffer
	commitments, err := open.SealContainer(&container, open.ContainerInput{
		Tenant:  tenant,
		Locator: "file-1",
		Version: 1,
		Body: open.ContainerInputBody{
			Key: key,
			Metadata: map[string]any{
				"name": "summary.txt",
				"type": "text/plain",
				"size": len(content),
			},
			Content: bytes.NewReader(content),
			Length:  len(content),
		},
	})
	if err != nil {
		return sealedFile{}, err
	}

	r := sealedFile{container: container.Bytes(), commitments: commitments}
	wrapContext := sealdcrypto.WrapContextContentKey{
		Tenant:  tenant,
		Locator: "file-1",
		Version: 1,
		Segment: "body",
	}
	for _, to := range recipients {
		wrapped, err := seal.Wrap(to, key, wrapContext)
		if err != nil {
			return sealedFile{}, err
		}
		r.wrapped = append(r.wrapped, wrapped)
	}
	return r, nil
}
```

### Read a file

A reader unwraps its slice of the envelope, then opens the container against the envelope it verified, never against the container's own header. `ContentStream` gives each frame's plaintext only once the frame is checked:

```go
// readFile unwraps the content key with the device's key, then streams
// the file's content from storage to w, checking each frame against the
// envelope the reader verified.
func readFile(
	device *open.DeviceKey,
	wrapped []byte,
	stored open.ContainerSource,
	envelope open.OpenContainerExpected,
	w io.Writer,
) error {
	key, err := open.Unwrap(device.Receiving(), wrapped,
		sealdcrypto.WrapContextContentKey{
			Tenant:  envelope.Tenant,
			Locator: envelope.Locator,
			Version: envelope.Version,
			Segment: "body",
		})
	if err != nil {
		return err
	}
	defer open.Zeroise(key)

	container, err := open.OpenContainer(stored, envelope)
	if err != nil {
		return err
	}
	content, err := container.ContentStream(key)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, content)
	return err
}
```

`stored` is any `open.ContainerSource`: `bytes.NewReader` over a container in memory, or an `*io.SectionReader` over a file or an object in storage. `Content(key, &open.ContentRange{...})` reads a range, and reads only the frames it needs. A range is inside `ContentLength(key)`, the content's length, which the metadata's `size` is too, since a frame 0 whose `size` is not the content's length is refused, and a range outside the content panics: at once where it runs past the body's plaintext, which the header gives, and once frame 0 is checked where it runs past the content alone, so a key or a frame that does not check is refused first.

### Check a restored container

A service that holds no key checks a container restored to storage against the envelope it holds: the header names that envelope, the size is the one the header gives, each frame list matches its root and each frame its leaf. `verify.CheckContainer` reads every byte once and decrypts nothing, so a service that imports `verify` alone runs it:

```go
// checkRestored checks each restored container against its envelope,
// and keeps nothing of it but its verdict.
func checkRestored(
	storage map[string]verify.ContainerSource,
	envelopes map[string]verify.CheckContainerExpected,
) map[string]error {
	verdicts := make(map[string]error, len(envelopes))
	for name, envelope := range envelopes {
		_, verdicts[name] = verify.CheckContainer(storage[name], envelope)
	}
	return verdicts
}
```

The check proves a container is the one its envelope commits to, never that the envelope is genuine, so the envelope's signature is verified where that matters. It checks no key commitment, which only a reader holding the content key can.

### Sign with a key in a key store

`sign.Sign` and `sign.Certify` take any `sign.Signer`, so a key a KMS or an HSM holds signs without leaving it. The signer is handed the whole labelled message, and what it returns is verified before `Sign` returns it:

```go
// KeyStore is a key store's client, such as a KMS or an HSM's, that signs
// under a key it holds and never exports.
type KeyStore interface {
	Sign(ctx context.Context, keyID string, message []byte) ([]byte, error)
}

// storeSigner is a sign.Signer over a key a KeyStore holds.
type storeSigner struct {
	store  KeyStore
	keyID  string
	public sealdcrypto.PublicKey
}

func (s storeSigner) PublicKey() sealdcrypto.PublicKey { return s.public }

func (s storeSigner) Sign(ctx context.Context, message []byte) ([]byte, error) {
	return s.store.Sign(ctx, s.keyID, message)
}
```

### Open a wrap with a key in a key store

`open.UnwrapWith` and `open.UnwrapDomainKeyWith` take any `open.Receiver`, so a device key that a hardware key store or a platform's custody holds, and that gives out no private half, still receives a wrap. The custody decapsulates the wrap's encapsulation to X-Wing's shared secret, and the library opens the wrap with it under the context the caller expects, refusing it as `open.Unwrap` and `open.UnwrapDomainKey` do. The custody is asked only once the wrap passes every check that reads no secret, and its own error is returned unchanged:

```go
// Custody is a hardware key store's client, such as a platform's, that
// holds a device key and never exports it: it decapsulates a wrap's
// encapsulation under the key, and gives out nothing else.
type Custody interface {
	Decapsulate(ctx context.Context, keyID string, enc []byte) ([]byte, error)
}

// custodyReceiver is an open.Receiver over a key a Custody holds.
type custodyReceiver struct {
	custody Custody
	keyID   string
	public  sealdcrypto.PublicKey
}

func (r custodyReceiver) PublicKey() sealdcrypto.PublicKey { return r.public }

func (r custodyReceiver) Decapsulate(
	ctx context.Context, enc []byte,
) ([]byte, error) {
	return r.custody.Decapsulate(ctx, r.keyID, enc)
}
```

A device's slice of an epoch's domain key is a `sealdcrypto.WrapContextDomainKey`, opened under the key digest of the epoch's domain key, which the epoch's signed body carries as `key_digest` and `verify.ReadEpochBody` reads. A domain key whose digest is another is refused `authentication-failed`, so a slice made wrong is refused at its first unwrap:

```go
key, err := open.UnwrapDomainKeyWith(ctx, receiver, wrapped, wrapContext, keyDigest)
if err != nil {
	log.Fatal(err)
}
defer key.Zeroise()
```

`key` is the epoch's domain key, an `*open.ReceivingKey` that opens what was wrapped to it, an earlier epoch's key through an `epoch-link` among them, under that epoch's digest. A wrap of any other purpose opens through `open.UnwrapWith` to the secret, the caller's to zeroise with `open.Zeroise` once used. The shared secret opens every wrap made to the key under any context, so a custody decapsulates only for the library that opens the wrap, and never hands it to a caller it would not let unwrap. A key this library holds is a `Receiver` itself, `open.ReceivingKey` and `open.DeviceKey` each decapsulating as a custody would.

### Issue and verify a card

The identity authority, here the `storeSigner` above, certifies a device's card: its public key, bound to the person and tenant it belongs to, with bytes as base64url without padding and times as RFC 3339 in whole seconds:

```go
// issueCard is the identity authority certifying a person's device key,
// for a year from now.
func issueCard(
	ctx context.Context,
	authority sign.Signer,
	tenant sealdcrypto.TenantID,
	person sealdcrypto.Person,
	device sealdcrypto.PublicKey,
	now time.Time,
) ([]byte, error) {
	personHash, err := verify.PersonHash(tenant, person)
	if err != nil {
		return nil, err
	}
	id := verify.RecipientID(device)
	return sign.Certify(ctx, authority, sealdcrypto.LabelCard, map[string]any{
		"recipient_id": b64(id[:]),
		"tenant_id":    tenant.String(),
		"person":       b64(personHash),
		"public_key": map[string]any{
			"algorithm": string(device.Algorithm()),
			"value":     b64(device.Value()),
		},
		"issued_at":   now.UTC().Format(time.RFC3339),
		"valid_until": now.UTC().AddDate(1, 0, 0).Format(time.RFC3339),
	})
}
```

Any component then checks the card offline, under the anchor compiled into its release:

```go
body, err := verify.VerifyCard(verify.VerifyCardInput{
	Card:              card,
	IdentityAuthority: authorityCertificate,
	Anchor:            anchor.PublicKey(), // compiled into the release
	Tenant:            tenant,
	Person:            person,
	At:                now,
})
```

A component that holds no anchor checks the card from its step 2, under the keys of the tenant's identity authorities it holds from a source it trusts for that tenant: one, and two while the anchor rotates, when the card passes under either. Nothing in the card ties those keys to the tenant, so a key never comes from the card's sender. Each key is checked to be an identity authority's before the card is read, and a list of none or of more than `verify.MaxIdentityAuthorities` is a fault:

```go
body, err = verify.VerifyCardUnderIdentityAuthority(
	verify.VerifyCardUnderIdentityAuthorityInput{
		Card:                  card,
		IdentityAuthorityKeys: authorityKeys,
		Tenant:                tenant,
		Person:                person,
		At:                    now,
	})
```

A signature kept and verified long after it was made, an epoch body's or an envelope's, is checked under its signer's card as a kept signature's, with no person and no instant: the card's steps 1 to 3 alone, so a card whose window has ended, or that was replaced or revoked since, still verifies what it signed. It says nothing of who signed or when, so it never admits a device. `verify.VerifyKeptCardUnderIdentityAuthority` makes the same check from step 2, under the identity authorities' keys:

```go
body, err = verify.VerifyKeptCard(verify.VerifyKeptCardInput{
	Card:              card,
	IdentityAuthority: authorityCertificate,
	Anchor:            anchor.PublicKey(), // compiled into the release
	Tenant:            tenant,
})
```

### Mint and recover the backup key

The backup key is an x-wing key an Owner's device mints with `open.GenerateReceivingKey`. Its registration is the canonical JSON of its tenant, key and fingerprint, which the minting device signs under `sealdcrypto.LabelRegistration`, and the identity authority under `sealdcrypto.LabelBackupKey`, over `verify.Tuple` of the registration and the device's signature. `open.EncodeRecoveryPhrase` writes the key's seed as 24 words, which the Owner keeps off every device:

```go
// mintBackupKey mints the tenant's backup key on an Owner's device: its
// registration, which the device signs, and its recovery phrase, which the
// Owner writes down once and the device never keeps.
func mintBackupKey(
	ctx context.Context, owner *open.DeviceKey, tenant sealdcrypto.TenantID,
) (registration, signature, phrase []byte, err error) {
	key := open.GenerateReceivingKey()
	defer key.Zeroise()
	public := key.PublicKey()
	registration, err = verify.CanonicalJSON(map[string]any{
		"tenant_id": tenant.String(),
		"public_key": map[string]any{
			"algorithm": string(public.Algorithm()), "value": b64(public.Value()),
		},
		"fingerprint": b64(verify.KeyDigest(public)),
	})
	if err != nil {
		return nil, nil, nil, err
	}
	signature, err = sign.Sign(ctx, owner, sealdcrypto.LabelRegistration, registration)
	if err != nil {
		return nil, nil, nil, err
	}
	return registration, signature, open.EncodeRecoveryPhrase(key), nil
}
```

To recover, the Owner types the phrase back, and `open.CheckRecoveryPhrase` gives the key only once its digest is the fingerprint the device pinned from the registration as signed. Taking what a person types into the phrase's one form, lower case and one space between words, is the caller's:

```go
// recoverBackupKey is the backup key an Owner types back, used only once
// its digest is the fingerprint pinned from the registration as signed.
func recoverBackupKey(typed []byte, pinned verify.RegistrationBody) (*open.ReceivingKey, error) {
	key, err := open.CheckRecoveryPhrase(typed, pinned.Fingerprint)
	if err != nil {
		var r *sealdcrypto.Refusal
		if errors.As(err, &r) && r.Kind == sealdcrypto.RefusalKindPhraseMismatch {
			return nil, errors.New("not the tenant's recovery phrase")
		}
		return nil, err
	}
	return key, nil
}
```

A re-founding's challenge is wrapped to the registered backup key with `seal/refoundingchallenge`, which wraps nothing else, and the recovered key opens it with `open.Unwrap` under `sealdcrypto.WrapContextRefoundingChallenge`. The phrase and the key are secrets: zeroise the phrase with `open.Zeroise` and the key with its `Zeroise` once used.

### Check a new device's call

Before its first session, a device with no card yet signs each call about its own request, and none about its card, under `sealdcrypto.LabelDeviceCall`, over a body of the tenant, the method, the path and query as sent, the SHA-256 of the call's body, and when it signed. The server rebuilds that body from the call it received, never from bytes the caller sends, and verifies the signature under the key the call's path names:

```go
// checkDeviceCall checks a call a device with no card yet signed about
// its own request: the body is rebuilt from the call as received, never
// taken from the caller, and its signature verified under the key the
// call's path names, at an instant within five minutes of the clock.
func checkDeviceCall(r *http.Request, payload []byte, device sealdcrypto.PublicKey,
	at time.Time, signature []byte, now time.Time) error {
	if at.Sub(now).Abs() > 5*time.Minute {
		return errors.New("a call signed at another time")
	}
	bodyHash := sha256.Sum256(payload)
	body, err := verify.CanonicalJSON(map[string]any{
		"tenant_id": tenant.String(),
		"method":    r.Method,
		"path":      r.RequestURI,
		"body_hash": b64(bodyHash[:]),
		"at":        at.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	if _, err := verify.ReadDeviceCallBody(body); err != nil {
		return err
	}
	if ok, err := verify.VerifySignature(device, sealdcrypto.LabelDeviceCall, body, signature); err != nil || !ok {
		return errors.New("not the device's call")
	}
	return nil
}
```

The bodies of a key domain's commits, `verify.ReadEpochBody`, `verify.ReadEscrowCommitBody` and `verify.ReadCommitBody`, are read from the bytes a signature verified, and what each hashes, such as `slices_hash`, compared with `verify.JSONHash` of what the request carries. A commit's `EventIDs` are compared with the events its lease was taken under, in their order, and its `CommitHash` covers each save's version envelope, so one signature commits a whole group of saves. Under `share` and `backfill`, a request to a record's recipients carries another body, a record recipient's commit, read by `verify.ReadRecordRecipientCommitBody`: the record's locator, the person hash of its recipient, the event and `slices_hash`, compared alike. Under `backfill`, a request to the tokenisation key's wraps carries a third, read by `verify.ReadTokenisationKeyBackfillBody`, whose `wraps_hash` is compared alike. The caller reads the body its request carries, and no reader takes another's. An epoch's `KeyDigest` is the key digest of its domain key, which every device gives `open.UnwrapDomainKey` for each unwrap of that key, from a slice or an `epoch-link`, so it is taken from an epoch body whose signature verified. The digest is compared once the wrap opens, so a receiver held elsewhere is asked whatever the digest. A service that holds the slices can wrap a key of its own to any device and hand out its digest beside it, so a key opened from a slice is used only once the device has rebuilt the epoch's body with `verify.CanonicalJSON`, from the tenant, the root, the slice's epoch and digest and the body's other members the service hands out with it, and verified its signature under `sealdcrypto.LabelEpoch` with `verify.VerifySignature`, under the signer's card checked as a kept signature's with `verify.VerifyKeptCard` under the device's anchor; a signature that does not verify refuses the slice `signature-invalid`, and the key is not used. A key opened from an `epoch-link` needs none: it only opens what was written under an earlier epoch, and a wrong key opens nothing. Where a key recovery finds an epoch whose backup slice opens to no key of its digest, the recovering Owner's device mints a fresh key for it and signs its epoch body, read as any other.

A member of a key domain made an owner rewrites no escrow, so its body is not a commit: `verify.ReadOwnershipBody` reads the tenant, the domain's root and the member's person hash, signed under `sealdcrypto.LabelOwnership`. The body names nothing fresh, so the same owner making the same member an owner signs the same bytes again, and a caller checks that a request is new by what it came with, never by the body.

A move of a record or a file to another key domain commits the rewrapped keys of every version in one body: `verify.ReadMoveBody` reads the tenant, the object's locator, the target's root, the event, the target's epoch the keys are wrapped to and `slices_hash`, signed under `sealdcrypto.LabelMove` by a domain owner's device key. The caller compares `slices_hash` with `verify.JSONHash` of the versions the request carries, and the epoch with the target's current one.

### Read a body by its purpose

A revocation, a suspension, a role given or removed, an Owner minimum asked, a passkey's registration and a key recovery each sign a body whose `purpose` is read first and names the members the rest of it holds, so a body signed for one purpose never passes for another. `verify.ReadRevocationBody`, `verify.ReadPersonStateBody`, `verify.ReadRoleBody`, `verify.ReadPasskeyBody` and `verify.ReadRecoveryBody` read them, and the caller switches on the body's `Purpose`, such as `verify.RevocationPurposeOffboard` or `verify.RolePurposeSetOwnerMinimum`, before it reads any other member: a member its purpose does not name is the zero value.

An account's reset, an AI agent's state and a session's manifest each sign a body of one form, read by `verify.ReadAccountBody`, `verify.ReadAgentStateBody` and `verify.ReadSessionManifestBody`. A manifest over an export is signed under the same label, and is laid out by the evidence pack, so no reader here takes one: the caller reads the body its request carries. Each reader checks the body's form alone, and who may sign it, such as an AI agent's delegator for a pause, is the caller's to check against the signer.

### Check a key recovery's bodies

A key recovery is asked, and its rebuilt escrows committed, under `sealdcrypto.LabelRecovery`, each read by `verify.ReadRecoveryBody`, switching on its `Purpose`. `verify.RecoveryPurposeAsk` is the asking Owner's device's request: the domains, or every domain, the new owner, a reason code and a reference, each read for its form alone, so which codes there are is the verifier's to check. It names nothing fresh, so the same ask signed twice gives the same bytes, and the request it comes in tells the two apart. `verify.RecoveryPurposeCommit` is the recovering Owner's device's commit: the recovery's id and `SlicesHash`, which the verifier compares with `verify.JSONHash` of the domains its request carries, rebuilding the body from the recovery the request names, so a commit made for another recovery does not verify.

### Take the unlock challenge

A fresh unlock is read by `verify.ReadUnlockBody`, and `verify.UnlockChallenge` is the challenge a passkey asserts over: the SHA-256 of the message the unlock body is signed as, taken only of a body the reader accepts. The client takes it over the body it rebuilt from what it asked before the touch, never over the server's bytes unchecked:

```go
// unlockChallenge is the challenge a passkey asserts over for a fresh
// unlock: the client rebuilds the unlock body from what it asked before
// the touch, compares it with the bytes the server laid out, and takes
// the challenge over its own bytes alone.
func unlockChallenge(rebuilt, fromServer []byte) ([]byte, error) {
	if !bytes.Equal(rebuilt, fromServer) {
		return nil, errors.New("an unlock the client did not ask for")
	}
	return verify.UnlockChallenge(rebuilt)
}
```

### Take the App Attest challenge

At a session's opening on iOS, App Attest asserts over a `clientDataHash`, which `verify.AppAttestChallenge` gives: the SHA-256 of the message the opening body is signed as under `sealdcrypto.LabelSession`, so the assertion commits to the same tenant, nonce and session key as the device key's signature. It is taken only of a body `verify.ReadSessionBody` reads as an opening: a resume, or any other purpose, is refused `malformed`, since only an opening is attested. The device takes it over the bytes it signs, and a server over the bytes whose signature it verified:

```go
// openWithAppAttest signs a session's opening and gives the clientDataHash
// App Attest asserts over, so the assertion sent beside the signature
// commits to the same tenant, nonce and session key.
func openWithAppAttest(ctx context.Context, device *open.DeviceKey, opening []byte) (signature, clientDataHash []byte, err error) {
	clientDataHash, err = verify.AppAttestChallenge(opening)
	if err != nil {
		return nil, nil, err
	}
	signature, err = sign.Sign(ctx, device, sealdcrypto.LabelSession, opening)
	if err != nil {
		return nil, nil, err
	}
	return signature, clientDataHash, nil
}
```

### Take a passkey challenge

Where a passkey seals a web client's device key, the WebAuthn registration or assertion sent beside an enrolment request, or beside a passkey body, is over the passkey challenge: the SHA-256 of the message the body is signed as. `verify.PasskeyChallengeEnrolment` takes it over an enrolment request and `verify.PasskeyChallengePasskey` over a passkey body, each only of a body its reader accepts, so the ceremony commits to the very bytes the device key signs:

```go
// enrolWithPasskey signs a new device's enrolment request and gives the
// challenge the passkey ceremony runs over, so the registration or
// assertion sent beside the request commits to that request alone.
func enrolWithPasskey(ctx context.Context, device *open.DeviceKey, request []byte) (signature, challenge []byte, err error) {
	challenge, err = verify.PasskeyChallengeEnrolment(request)
	if err != nil {
		return nil, nil, err
	}
	signature, err = sign.Sign(ctx, device, sealdcrypto.LabelEnrolment, request)
	if err != nil {
		return nil, nil, err
	}
	return signature, challenge, nil
}
```

### Hash a session secret

A session secret travels as text, its base64url, and is hashed over that text, never over the 256 bits it encodes. `verify.TextSecretHash` hashes a secret that travels as text, a session secret or a link key, over its UTF-8 exactly as given, and refuses text that is not well-formed Unicode `malformed`. A session secret's is the SHA-256 of the access token that RFC 9449, section 4.2, lays out for a DPoP proof's `ath`, and the hash a server keeps in place of the secret, so the two are one value. A server that draws a secret hashes the text it returns. `verify.SecretHash` hashes a secret's bytes, and a session secret's bytes given to it hash to a value no proof carries:

```go
// proofAth is the ath of a DPoP proof sent with a session secret: the
// secret hash of the secret's text, exactly as it travels, never of the
// bytes it decodes to, in base64url without padding.
func proofAth(sessionSecret string) (string, error) {
	h, err := verify.TextSecretHash(sessionSecret)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(h), nil
}
```

### Check the tokenisation key

The client that mints an epoch of the tenant's tokenisation key sends its `verify.TokenisationCheck`, and every device that unwraps that epoch checks the key it opened before it uses it, so no device makes refs under a key the others do not hold:

```go
// tokenisationKey unwraps the tenant's tokenisation key of epoch and
// checks it against the check the server kept for that epoch, before
// it makes a ref under it.
func tokenisationKey(device *open.DeviceKey, wrapped []byte, epoch uint64, check []byte) ([]byte, error) {
	key, err := open.Unwrap(device.Receiving(), wrapped,
		sealdcrypto.WrapContextTokenisationKey{Tenant: tenant, Epoch: epoch})
	if err != nil {
		return nil, err
	}
	if err := verify.CheckTokenisationKey(epoch, key, check); err != nil {
		open.Zeroise(key)
		return nil, err
	}
	return key, nil
}
```

### Save a folder index

A key domain's folder index is a container of its own, of one segment whose plaintext is its canonical JSON alone. `open.SealFolderIndex` panics on an index a reader would refuse, a fault, and `open.ReadFolderIndex` reads one in its one order, its format before any other member. It reads format 3, which `open.IndexFormat` names and a writer writes, format 2, which is format 3 without `name`, and format 1, which is format 2 without `hidden`; `FolderIndex.Format` says which it read. In format 3, `name` is the key domain's own name, non-empty text, and absent until a client writes it; `FolderIndex.Name` gives it, or `""` where the index holds none, and a `name` in format 1 or 2 is refused `malformed`. An entry whose `hidden` is set, `import-records` on a key domain's entry or `import-record` on a file's, is one a client leaves out of a listing until its person reveals it. An index of a format it does not know is refused `unsupported`, so a reader never rewrites it:

```go
// saveIndex seals a key domain's folder index as the version its commit
// lease names, and returns the container, the commitment its envelope
// signs, and its content key.
func saveIndex(root sealdcrypto.Locator, version uint64, entries []any) ([]byte, open.SegmentCommitment, []byte, error) {
	key := open.NewContentKey()
	var container bytes.Buffer
	commitment, err := open.SealFolderIndex(&container, open.FolderIndexInput{
		Tenant: tenant, Root: root, Version: version, Key: key,
		Body: map[string]any{"format": open.IndexFormat, "entries": entries},
	})
	return container.Bytes(), commitment, key, err
}
```

A pre-image journal is sealed by `open.SealJournal` under `open.JournalLocator(lease)`, `journal/{lease_id}`, at version 1, and read by `open.ReadJournal`, which refuses `authentication-failed` an envelope naming another lease's locator, an empty one among them, or another version, before it reads a byte of the journal:

```go
// readJournal reads the pre-image journal a commit lease came with,
// against the envelope the reader verified for that lease: one save for
// each the lease names, in its order, each the version's envelope, which
// the caller verifies before it commits it, and the entry the writer was
// about to write.
func readJournal(
	stored open.ContainerSource,
	envelope open.OpenContainerExpected,
	lease sealdcrypto.UUID,
	key []byte,
) ([]open.JournalSave, error) {
	journal, err := open.ReadJournal(stored, envelope, lease, key)
	if err != nil {
		return nil, err
	}
	return journal.Saves, nil
}
```

### Verify a timestamp token

A checkpoint's RFC 3161 token is checked over the trail's head, under the timestamp authorities' roots compiled into the release, for example with `//go:embed`, never fetched or taken from the token:

```go
// checkpointTime is the time a trail's head existed at, by a timestamp
// authority's token over it.
func checkpointTime(token, head []byte) (time.Time, error) {
	r, err := verify.VerifyTimestamp(token, head, timestampRoots, nil)
	if err != nil {
		return time.Time{}, err
	}
	return r.Time, nil
}
```

From 2036, when NIST IR 8547 disallows ECDSA and RSA, every token is refused, as [Limitations](#limitations) explains.

## Benchmarks

The median of six runs on an Apple M2, darwin/arm64, Go 1.27.1, on 2026-09-30, and the recovery phrase's on Go 1.27.2, on 2026-10-15. Runs spread up to 30% on a laptop, so each figure is an order of magnitude, not a bound.

| Operation                                      | Time    | Throughput |
| ---------------------------------------------- | ------- | ---------- |
| `sign.GenerateSigningKey`                      | 185 µs  |            |
| `open.GenerateReceivingKey`                    | 76 µs   |            |
| `open.GenerateDeviceKey`                       | 249 µs  |            |
| `verify.ImportPublicKey`, a device key         | 94 µs   |            |
| `sign.Sign`, both halves signed and verified   | 646 µs  |            |
| `verify.VerifySignature`                       | 156 µs  |            |
| `verify.ReadCertificate`                       | 165 µs  |            |
| `seal.Wrap`                                    | 125 µs  |            |
| `open.Unwrap`                                  | 90 µs   |            |
| `open.SealContainer`, 4 KiB                    | 11 µs   | 351 MiB/s  |
| `open.SealContainer`, 1 MiB                    | 737 µs  | 1.33 GiB/s |
| `open.SealContainer`, 16 MiB                   | 10.2 ms | 1.53 GiB/s |
| `OpenContainer` and `Content` whole, 4 KiB     | 7.7 µs  | 510 MiB/s  |
| `OpenContainer` and `Content` whole, 1 MiB     | 916 µs  | 1.07 GiB/s |
| `OpenContainer` and `Content` whole, 16 MiB    | 13.1 ms | 1.20 GiB/s |
| `OpenContainer` and `Content`, 4 KiB of 16 MiB | 99 µs   |            |
| `OpenContainer` and `Metadata`, of 16 MiB      | 51 µs   |            |
| `open.EncodeRecoveryPhrase`                    | 317 µs  |            |
| `open.CheckRecoveryPhrase`                     | 359 µs  |            |
| `open.Ref`                                     | 0.45 µs |            |
| `verify.VerifyTimestamp`, SSL.com, ECDSA P-256 | 581 µs  |            |
| `verify.VerifyTimestamp`, DigiCert, RSA 4096   | 475 µs  |            |
| `verify.VerifyTimestamp`, GlobalSign, RSA 3072 | 596 µs  |            |

## Limitations

- **Timestamp renewal.** `verify.VerifyTimestamp` verifies an RFC 4998 evidence record given with a token still in date, and refuses the token where the record fails. No archive timestamp past 2035 is accepted until a signature accepted past it is named, so from 2036 every token is refused, whatever evidence record it is given. A record that renews its hash tree, holding more than one chain, is refused, since SHA-256 is its only hash.
- **Session keys.** `verify.ReadSessionBody` checks a session key for its form alone, as the Crypto API, Bodies, sets it: a `p-256` point is not checked to be on the curve, which the Crypto API leaves open, so a caller parses it with a parser that checks it before it verifies a proof under it.
- **Unaudited packages.** `crypto/mldsa`, `crypto/hpke` and `encoding/json/jsontext` are outside the audit under [Primitives](#primitives).
- **FIPS 140-3 mode.** The library does not run under `GODEBUG=fips140=only`. There `crypto/cipher` refuses AES-GCM under a nonce the caller sets, which every frame's is, so sealing or opening a container panics. `crypto/ecdh` refuses X25519 outside `crypto/hpke` there too, so `open.UnwrapWith` and each key's `Decapsulate` panic, whatever their input.

## Documentation

[API documentation](docs/README.md) describes the library's types, operations and error conventions.

## Security

Report a security issue to security@sealdhealthcare.com, the one channel for it, and never in a public issue or a pull request.

## License

Proprietary. Copyright Seald Healthcare. See [LICENSE](LICENSE).

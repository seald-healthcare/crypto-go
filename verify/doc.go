// Package verify reads and checks public values: canonical JSON and tuples, a code's text, hashes, public keys and
// their fingerprint words, verifying signatures, certificates, cards and timestamp tokens, and reading
// each signed body the format lays out from its bytes as signed, an unlock body's challenge, a session
// opening's App Attest challenge and the passkey challenge of an enrolment request and of a passkey body
// among them, and checking a whole container against its envelope with no key.
// It holds no private key and nothing that signs, wraps or decrypts, so a service that only checks
// signatures imports this package alone. The secrets it takes it keeps none of: a tokenisation key,
// which TokenisationCheck hashes and CheckTokenisationKey checks, and a setup code or a guest code, which
// EncodeCode writes, DecodeCode reads and SecretHash hashes.
package verify

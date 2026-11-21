// Package sign generates a signing key, imports one from its signing seed, derives an identity
// authority from the authority seed, signs under a label, certifies a body, and zeroises a signing key
// it returns, so a service that links it without open, such as one that holds the anchor and every
// identity authority, holds and wipes its keys. The module is split by capability, so only a service
// that signs imports sign, and one that only verifies never links the code that signs.
package sign

// Package open is the package that decrypts: it generates device and receiving keys, unwraps a secret,
// or a domain key under its epoch's key digest, under a key it holds or under one held elsewhere that
// decapsulates, decapsulates for a key it holds, seals and opens content, a key domain's folder index
// and a pre-image journal among it, computes derivations, and writes and checks the backup key's
// recovery phrase. No other package of the module links it, so a service that must never decrypt
// leaves it out.
package open

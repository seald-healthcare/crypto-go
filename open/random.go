package open

import "crypto/rand"

// Random is length bytes from the operating system's CSPRNG, through crypto/rand, which is the only
// randomness this library draws. It never fails: crypto/rand stops the program rather than return
// bytes that are not random.
//
// A negative length is a fault, and panics. The bytes are the caller's, and a caller that uses them as
// a secret zeroises them with Zeroise once done.
func Random(length int) []byte {
	if length < 0 {
		panic("open: Random: negative length")
	}
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return b
}

// Zeroise overwrites secret with zeros, for a secret the caller holds once it is done with it, such as
// the bytes from ExportPrivateKey.
//
// It is best effort, the residual risk of a runtime with a garbage collector: it clears only the bytes
// secret points to, and not a copy the runtime or the caller made, such as the array an append
// outgrew. A secret is kept in one slice from the start, and never converted to a string.
func Zeroise(secret []byte) {
	clear(secret)
}

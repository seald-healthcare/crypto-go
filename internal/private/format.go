package private

import (
	"fmt"
	"io"
)

// Each key formats, under every verb, as its contract name, algorithm and recipient id, so no format
// prints a seed or an expanded key. String and GoString give the same, for a caller that asks for them
// outside fmt. The receivers are values, so a key and a pointer to it both do.
//
// A key fmt reaches through reflection, as an unexported field of a struct of the caller's, whose
// methods it cannot call, prints its fields instead: its secrets' pointer, an address under every verb,
// and its public half. A Device's halves are pointers, each to a key that holds its secrets so.

// Format writes the key's name, algorithm and recipient id.
func (r Receiving) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, r.String())
}

// String is the key's name, algorithm and recipient id.
func (r Receiving) String() string { return r.public.Describe("ReceivingKey") }

// GoString is String.
func (r Receiving) GoString() string { return r.String() }

// Format writes the key's name, algorithm and recipient id.
func (s Signing) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, s.String())
}

// String is the key's name, algorithm and recipient id.
func (s Signing) String() string { return s.public.Describe("SigningKey") }

// GoString is String.
func (s Signing) GoString() string { return s.String() }

// Format writes the key's name, algorithm and recipient id.
func (d Device) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, d.String())
}

// String is the key's name, algorithm and recipient id.
func (d Device) String() string { return d.public.Describe("DeviceKey") }

// GoString is String.
func (d Device) GoString() string { return d.String() }

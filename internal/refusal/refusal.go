// Package refusal makes the refusals the parts return. Every refusal this library returns is made by
// New, so its detail is a constant the compiler has checked, and never a value built from the input.
package refusal

import sealdcrypto "github.com/seald-healthcare/crypto-go"

// detail is unexported so that only an untyped string constant converts to it: a variable, or
// fmt.Sprintf over the input, does not compile as a detail.
type detail string

// New is the refusal of kind, with detail, a constant phrase for logs.
func New(kind sealdcrypto.RefusalKind, d detail) *sealdcrypto.Refusal {
	return &sealdcrypto.Refusal{Kind: kind, Detail: string(d)}
}

// Package sealdcrypto holds the types that the packages verify, sign, seal and open all share,
// and no private key. The module is split by capability, so a service imports only what it needs:
// one that only checks signatures imports verify alone, and one that must never decrypt leaves out
// open.
package sealdcrypto

// Contract is the version of the Crypto API this module implements, as every label and format string
// carries it.
const Contract = "v1"

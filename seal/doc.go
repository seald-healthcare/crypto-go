// Package seal wraps a secret to a public key. The module is split by capability, so a service that
// wraps secrets to devices imports seal without open, and never links the code that unwraps them.
package seal

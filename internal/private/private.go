// Package private is the private keys under open.ReceivingKey, sign.SigningKey and open.DeviceKey, each
// made from its private half as the contract's Keys sets (the Crypto API, Keys).
//
// Each handle keeps its seed, the private half exportPrivateKey returns, and the keys the standard
// library expands from it. A handle cannot zeroise the standard library's expanded keys, which live
// until the garbage collector frees them: the residual the contract names for such a runtime. A seed
// given to a constructor is copied, and the caller zeroises its own.
package private

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/mldsa"
	"crypto/mlkem"
	"errors"

	"github.com/seald-healthcare/crypto-go/internal/encoding"
	"github.com/seald-healthcare/crypto-go/internal/public"
	"github.com/seald-healthcare/crypto-go/internal/xwing"
)

// Each private half's size.
const (
	XWingSeedSize   = xwing.SeedSize
	SigningSeedSize = 32
	DeviceSeedSize  = XWingSeedSize + SigningSeedSize
)

var errSeedSize = errors.New("private: a private half of the wrong size")

// Sealed is embedded in open.PrivateKey, so that only the handles over Receiving, Signing and Device
// satisfy it: its method is this package's, which no other package can declare.
type Sealed interface {
	sealed()
}

// seal is embedded in each key, so a handle defined over one keeps its promoted method, as a defined
// type keeps the fields of the struct under it.
type seal struct{}

func (seal) sealed() {}

// incomparable is a field of no size that no == compares, so a key is not comparable and is no map's
// key: two handles of one key would compare unequal, and a copy of one equal, which an identity check
// would get wrong. Two keys are the same key when their PublicKey()s are equal.
type incomparable [0]func()

// hide is p behind a second pointer, where fmt prints an address under every verb.
func hide[T any](p *T) **T {
	return &p
}

// Receiving is an x-wing key. Its secrets are behind two pointers, so a Receiving copied by value into
// a struct of the caller's, where fmt reaches it through reflection and cannot call its Format, prints
// an address and never a seed. One pointer is not enough: under a verb that does not fit a pointer,
// such as %s, fmt prints the pointer again as a top-level value, and so prints the struct it points to.
type Receiving struct {
	_ incomparable
	seal
	secret **receivingSecret
	public public.Key
}

// receivingSecret is a Receiving's private half and the keys the standard library expands from it: the
// key HPKE opens a wrap with, and its ML-KEM-768 and X25519 halves, which decapsulate an encapsulation to
// its shared secret alone, since crypto/hpke gives none out.
type receivingSecret struct {
	seed   []byte
	key    hpke.PrivateKey
	mlkem  *mlkem.DecapsulationKey768
	x25519 *ecdh.PrivateKey
}

var errHalves = errors.New("private: an x-wing key whose halves are not its public value")

// NewReceiving is the x-wing key whose private half is seed, X-Wing's seed. Its ML-KEM-768 and X25519
// halves are expanded from seed as the draft sets, and must give the public value crypto/hpke gives, or
// it returns an error, which no seed of the right size makes.
func NewReceiving(seed []byte) (*Receiving, error) {
	if len(seed) != XWingSeedSize {
		return nil, errSeedSize
	}
	k, err := xwing.NewPrivateKey(seed)
	if err != nil {
		return nil, err
	}
	expanded := xwing.Expand(seed)
	defer clear(expanded)
	m, err := mlkem.NewDecapsulationKey768(expanded[:mlkem.SeedSize])
	if err != nil {
		return nil, err
	}
	x, err := ecdh.X25519().NewPrivateKey(expanded[mlkem.SeedSize:])
	if err != nil {
		return nil, err
	}
	value := k.PublicKey().Bytes()
	if !bytes.Equal(value, append(m.EncapsulationKey().Bytes(), x.PublicKey().Bytes()...)) {
		return nil, errHalves
	}
	secret := &receivingSecret{seed: bytes.Clone(seed), key: k, mlkem: m, x25519: x}
	return &Receiving{secret: hide(secret), public: public.New(public.XWing, value)}, nil
}

// Public is the key's public half. The zero Receiving has none, nor one zeroised.
func (r *Receiving) Public() public.Key {
	if r.secret == nil || *r.secret == nil {
		return public.Key{}
	}
	return r.public
}

// Seed is the private half, in a new slice the caller zeroises. The zero Receiving has none, nor one
// zeroised.
func (r *Receiving) Seed() []byte {
	if r.secret == nil || *r.secret == nil {
		return nil
	}
	return bytes.Clone((*r.secret).seed)
}

// HPKE is the key as HPKE decapsulates with it. The zero Receiving has none, nor one zeroised.
func (r *Receiving) HPKE() hpke.PrivateKey {
	if r.secret == nil || *r.secret == nil {
		return nil
	}
	return (*r.secret).key
}

// XWing is the key's ML-KEM-768 and X25519 halves, as X-Wing decapsulates with them. The zero
// Receiving has none, nor one zeroised.
func (r *Receiving) XWing() (*mlkem.DecapsulationKey768, *ecdh.PrivateKey) {
	if r.secret == nil || *r.secret == nil {
		return nil, nil
	}
	return (*r.secret).mlkem, (*r.secret).x25519
}

// Zeroise overwrites the key's private half with zeros and drops what the standard library expanded
// from it, which hpke.PrivateKey, mlkem.DecapsulationKey768 and ecdh.PrivateKey give no way to
// overwrite, so it lives until the garbage collector frees it. The key, and every copy of its handle, is then the zero key. It is best effort, as the
// contract's Keys sets for a runtime with a garbage collector.
func (r *Receiving) Zeroise() {
	if r.secret == nil || *r.secret == nil {
		return
	}
	clear((*r.secret).seed)
	*r.secret = nil
}

// Signing is an ed25519+ml-dsa-65 key made from its signing seed. Its secrets are behind two pointers,
// as Receiving's are.
type Signing struct {
	_ incomparable
	seal
	secret **signingSecret
	public public.Key
}

// signingSecret is a Signing's private half and the keys the standard library expands from it.
type signingSecret struct {
	seed    []byte
	ed25519 ed25519.PrivateKey
	mldsa   *mldsa.PrivateKey
}

// NewSigning is the ed25519+ml-dsa-65 key whose private half is seed, a signing seed: Ed25519's secret
// key is HKDF(seed, "seald/v1/sign/ed25519"), and ML-DSA-65's key pair is ML-DSA.KeyGen_internal(ξ)
// with ξ = HKDF(seed, "seald/v1/sign/ml-dsa-65"), each 32 bytes.
func NewSigning(seed []byte) (*Signing, error) {
	if len(seed) != SigningSeedSize {
		return nil, errSeedSize
	}
	secret := encoding.HKDF(seed, "seald/v1/sign/ed25519", ed25519.SeedSize)
	defer clear(secret)
	xi := encoding.HKDF(seed, "seald/v1/sign/ml-dsa-65", mldsa.PrivateKeySize)
	defer clear(xi)

	ml, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), xi)
	if err != nil {
		return nil, err
	}
	ed := ed25519.NewKeyFromSeed(secret)
	value := append(bytes.Clone(ed.Public().(ed25519.PublicKey)), ml.PublicKey().Bytes()...)
	return &Signing{secret: hide(&signingSecret{seed: bytes.Clone(seed), ed25519: ed, mldsa: ml}), public: public.New(public.Ed25519MLDSA65, value)}, nil
}

// Public is the key's public half. The zero Signing has none, nor one zeroised.
func (s *Signing) Public() public.Key {
	if s.secret == nil || *s.secret == nil {
		return public.Key{}
	}
	return s.public
}

// Seed is the private half, in a new slice the caller zeroises. The zero Signing has none, nor one
// zeroised.
func (s *Signing) Seed() []byte {
	if s.secret == nil || *s.secret == nil {
		return nil
	}
	return bytes.Clone((*s.secret).seed)
}

// Zeroise overwrites the key's private half and its Ed25519 key with zeros, and drops its ML-DSA-65
// key, which mldsa.PrivateKey gives no way to overwrite, so it lives until the garbage collector frees
// it. The key, and every copy of its handle, is then the zero key. It is best effort, as the contract's
// Keys sets for a runtime with a garbage collector.
func (s *Signing) Zeroise() {
	if s.secret == nil || *s.secret == nil {
		return
	}
	clear((*s.secret).seed)
	clear((*s.secret).ed25519)
	*s.secret = nil
}

// Sign is Ed25519.Sign(message) ‖ ML-DSA-65.Sign(message, context ""), both over the whole message:
// Ed25519 as RFC 8032 sets, and ML-DSA-65 as FIPS 204's ML-DSA.Sign, hedged with fresh randomness
// from crypto/rand. The caller has checked that message is a signature's, and that the key is not the
// zero key.
func (s *Signing) Sign(message []byte) []byte {
	ml, err := (*s.secret).mldsa.Sign(nil, message, &mldsa.Options{})
	if err != nil {
		panic("sign: " + err.Error())
	}
	return append(ed25519.Sign((*s.secret).ed25519, message), ml...)
}

// SignDeterministic is Sign with ML-DSA-65's rnd of 32 zero bytes, FIPS 204's deterministic variant,
// for the vectors alone: signing in use keeps fresh randomness.
func (s *Signing) SignDeterministic(message []byte) []byte {
	ml, err := (*s.secret).mldsa.SignDeterministic(message, &mldsa.Options{})
	if err != nil {
		panic("sign: " + err.Error())
	}
	return append(ed25519.Sign((*s.secret).ed25519, message), ml...)
}

// Device is an x-wing+ed25519+ml-dsa-65 key: it receives as its x-wing half and signs as the rest.
type Device struct {
	_ incomparable
	seal
	receiving *Receiving
	signing   *Signing
	public    public.Key
}

// NewDevice is the device key whose private half is seed: the X-Wing seed, then the signing seed.
func NewDevice(seed []byte) (*Device, error) {
	if len(seed) != DeviceSeedSize {
		return nil, errSeedSize
	}
	r, err := NewReceiving(seed[:XWingSeedSize])
	if err != nil {
		return nil, err
	}
	s, err := NewSigning(seed[XWingSeedSize:])
	if err != nil {
		return nil, err
	}
	value := append(r.public.Value(), s.public.Value()...)
	return &Device{receiving: r, signing: s, public: public.New(public.XWingEd25519MLDSA65, value)}, nil
}

// Public is the key's public half. The zero Device has none, nor one either half of which is zeroised.
func (d *Device) Public() public.Key {
	if d.receiving == nil || d.signing == nil || d.receiving.Public().IsZero() || d.signing.Public().IsZero() {
		return public.Key{}
	}
	return d.public
}

// Seed is the private half, in a new slice the caller zeroises. The caller has checked that the key is
// not the zero key.
func (d *Device) Seed() []byte {
	return append(d.receiving.Seed(), d.signing.Seed()...)
}

// Zeroise zeroises both halves, as Receiving's and Signing's Zeroise do, and the key is then the zero
// key.
func (d *Device) Zeroise() {
	if d.receiving != nil {
		d.receiving.Zeroise()
	}
	if d.signing != nil {
		d.signing.Zeroise()
	}
}

// Receiving is the key's x-wing half.
func (d *Device) Receiving() *Receiving {
	return d.receiving
}

// Signing is the key's ed25519+ml-dsa-65 half.
func (d *Device) Signing() *Signing {
	return d.signing
}

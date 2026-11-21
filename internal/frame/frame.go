// Package frame is the contract's Frames for open: a segment's frame key and base nonce from its
// content key and its place, and each frame of the chunk cipher, sealed and opened on its own. It
// decrypts, so only open links it.
//
// Its integers are little-endian, as the chunk cipher lays them out, where every other value of the
// contract is big-endian: the index a frame leads with, and the index and S in its additional data. The
// nonce's index alone is big-endian.
package frame

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/encoding"
	"github.com/seald-healthcare/crypto-go/internal/layout"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
)

const (
	// Size is S: the plaintext of every frame of a segment but its last, which is shorter.
	Size = layout.FrameSize
	// ContentKeySize is a content key's size.
	ContentKeySize = 32
	// Overhead is what a frame adds to its plaintext: the index it leads with and AES-256-GCM's tag.
	Overhead = indexSize + tagSize
	// Limit is the first index outside the format: an index is below 2^48.
	Limit = 1 << 48

	indexSize = 8
	tagSize   = 16
	keySize   = 32
	nonceSize = 12
)

// fin ends the additional data of a segment's last frame alone.
var fin = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// Keys is one segment's frame key, as AES-256-GCM, and its base nonce. It holds a secret: formatting it
// prints nothing of either, and no method returns them.
//
// A segment's keys come from a content key minted for that segment of that version alone, so no two
// segments share a frame key and a nonce: Keys is never reused for another segment, as the content key
// is never reused.
type Keys struct {
	aead      cipher.AEAD
	baseNonce [nonceSize]byte
}

// Format writes nothing of the keys, under every verb.
func (Keys) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("frame.Keys"))
}

var malformedText = refusal.New(sealdcrypto.RefusalKindMalformed, "text that is not well-formed Unicode")

// SegmentKeys is the segment's keys: frameKey ‖ baseNonce = HKDF(contentKey, "seald/v1/segment",
// tenant id, locator, version, segment), 32 and 12 bytes. A locator or a segment that is not well-formed
// Unicode is refused malformed.
//
// contentKey is the segment's content key, which SegmentKeys never keeps: the caller zeroises it. A
// content key that is not 32 bytes, and an empty locator, which the caller gives, are faults, and panic
// whatever else is given. So does Go's FIPS 140-only mode, which
// refuses AES-GCM under a nonce the caller sets, as every frame's is.
func SegmentKeys(contentKey []byte, tenant sealdcrypto.TenantID, locator sealdcrypto.Locator, version uint64, segment string) (*Keys, error) {
	okm, err := schedule(contentKey, tenant, locator, version, segment)
	if err != nil {
		return nil, err
	}
	defer clear(okm)
	return NewKeys(okm[:keySize], okm[keySize:]), nil
}

// schedule is SegmentKeys' frameKey ‖ baseNonce, a secret the caller zeroises, which only a test of
// frames/ reads as bytes.
func schedule(contentKey []byte, tenant sealdcrypto.TenantID, locator sealdcrypto.Locator, version uint64, segment string) ([]byte, error) {
	if len(contentKey) != ContentKeySize {
		panic("frame: a content key that is not 32 bytes")
	}
	if locator == "" {
		panic("frame: an empty locator")
	}
	l, ok1 := encoding.Text(string(locator))
	s, ok2 := encoding.Text(segment)
	if !ok1 || !ok2 {
		return nil, malformedText
	}
	return encoding.HKDF(contentKey, "seald/v1/segment", keySize+nonceSize, encoding.UUID(tenant), l, encoding.U64(version), s), nil
}

// NewKeys is the keys of a frame key and a base nonce, 32 and 12 bytes, which it never keeps: a
// segment's, as SegmentKeys derives them, or a vector's, which gives them as they are. Either of
// another size is a fault, and panics.
func NewKeys(frameKey, baseNonce []byte) *Keys {
	if len(frameKey) != keySize || len(baseNonce) != nonceSize {
		panic("frame: a frame key or base nonce of another size")
	}
	block, err := aes.NewCipher(frameKey)
	if err != nil {
		panic("frame: " + err.Error())
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic("frame: " + err.Error())
	}
	k := &Keys{aead: aead}
	copy(k.baseNonce[:], baseNonce)
	return k
}

func count(n, s uint64) uint64 {
	return n/s + 1
}

// SealSegment is plaintext cut into frames and each sealed in order, the frames one after another.
// header is the container's, bound to frame 0 alone. A plaintext of 2^48 frames or more is a fault, and
// panics.
func (k *Keys) SealSegment(header, plaintext []byte) []byte {
	return k.sealSegment(Size, header, plaintext)
}

func (k *Keys) sealSegment(s uint64, header, plaintext []byte) []byte {
	out := make([]byte, 0, uint64(len(plaintext))+count(uint64(len(plaintext)), s)*Overhead)
	var i uint64
	for ; uint64(len(plaintext)) >= s; i++ {
		out = append(out, k.seal(i, s, false, header, plaintext[:s])...)
		plaintext = plaintext[s:]
	}
	return append(out, k.seal(i, s, true, header, plaintext)...)
}

// Seal is frame i: u64le(i) ‖ AES-256-GCM(frameKey, nonce_i, aad_i, plaintext) ‖ tag, 24 bytes over
// plaintext, with header bound on frame 0 alone and the last frame marked as last. plaintext is S bytes,
// or no more on the last frame, which the cut makes shorter.
//
// An index of 2^48 or more, and a plaintext of another length, are faults, and panic.
func (k *Keys) Seal(i uint64, last bool, header, plaintext []byte) []byte {
	return k.seal(i, Size, last, header, plaintext)
}

func (k *Keys) seal(i, s uint64, last bool, header, plaintext []byte) []byte {
	if i >= Limit {
		panic("frame: an index of 2^48 or more")
	}
	if n := uint64(len(plaintext)); n > s || !last && n != s {
		panic("frame: a plaintext that is not its frame's length")
	}
	nonce := k.nonce(i)
	out := binary.LittleEndian.AppendUint64(make([]byte, 0, indexSize+len(plaintext)+tagSize), i)
	return k.aead.Seal(out, nonce[:], plaintext, aad(i, s, last, header))
}

// Open is frame i's plaintext, the frame read on its own, as a ranged read reads it. last and header
// are what the caller expects of frame i, from the container's header, and never from the frame.
//
//   - A frame whose leading index is not i, or an i of 2^48 or more, is refused out-of-range. The
//     leading index is checked before the frame is decrypted, as the Crypto API, Frames, sets, so a
//     frame moved within its segment, which leads with its own index, is refused out-of-range.
//   - A frame relabelled with i, cut short, read under another chunk size, read as last when it is not
//     or as not when it is, or read as frame 0 under another header, is refused authentication-failed.
//     So is a frame at its own index in another segment or version, which another content key seals.
//
// The plaintext is a new slice, the caller's to zeroise.
func (k *Keys) Open(i uint64, last bool, header, frame []byte) ([]byte, error) {
	return k.open(i, Size, last, header, frame)
}

var (
	outsideFormat = refusal.New(sealdcrypto.RefusalKindOutOfRange, "a frame index outside the format")
	otherIndex    = refusal.New(sealdcrypto.RefusalKindOutOfRange, "a frame whose leading index is not the one asked for")
	notOpened     = refusal.New(sealdcrypto.RefusalKindAuthenticationFailed, "a frame that does not open under the key and place asked for")
)

func (k *Keys) open(i, s uint64, last bool, header, frame []byte) ([]byte, error) {
	if i >= Limit {
		return nil, outsideFormat
	}
	if len(frame) < indexSize {
		return nil, notOpened
	}
	if binary.LittleEndian.Uint64(frame) != i {
		return nil, otherIndex
	}
	if n := uint64(len(frame)); n < Overhead || n > s+Overhead || !last && n != s+Overhead {
		return nil, notOpened
	}
	nonce := k.nonce(i)
	plaintext, err := k.aead.Open(nil, nonce[:], frame[indexSize:], aad(i, s, last, header))
	if err != nil {
		return nil, notOpened
	}
	return plaintext, nil
}

// nonce is nonce_i: the base nonce with bytes 4 to 11 XOR u64be(i).
func (k *Keys) nonce(i uint64) [nonceSize]byte {
	n := k.baseNonce
	binary.BigEndian.PutUint64(n[4:], binary.BigEndian.Uint64(n[4:])^i)
	return n
}

// aad is aad_i: u64le(i) ‖ u64le(S) ‖ header on frame 0 alone ‖ 0xFF × 8 on the last frame alone.
func aad(i, s uint64, last bool, header []byte) []byte {
	a := binary.LittleEndian.AppendUint64(nil, i)
	a = binary.LittleEndian.AppendUint64(a, s)
	if i == 0 {
		a = append(a, header...)
	}
	if last {
		a = append(a, fin...)
	}
	return a
}

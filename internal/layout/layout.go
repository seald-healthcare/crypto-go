// Package layout is the contract's Container and Frame list with no key: a container's header read
// and checked against its envelope, its size, and each frame list and frame against its root and leaf.
// It takes no content key and decrypts nothing, so verify links it.
package layout

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"math"
	"slices"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/encoding"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
)

const (
	// Label is a v1 header's first part.
	Label = "seald/v1/container"
	// FrameSize is S: the plaintext of every frame of a segment but its last, which is shorter.
	FrameSize = 65536
	// Overhead is what a frame adds to its plaintext: the u64le index it leads with and its 16-byte tag.
	Overhead = 24
	// FlagsSize is the flags' size.
	FlagsSize = 2
	// LeafSize is a leaf's and a root's size, and the frame list's for each frame.
	LeafSize = sha256.Size
	// MaxFrames is the most frames a segment has a root for: its frame list is a tuple's part, whose
	// u32be length holds no more than 2^32 - 1 bytes, 2^27 - 1 leaves.
	MaxFrames = math.MaxUint32 / LeafSize
	// MaxSegments is the most segments a container holds.
	MaxSegments = 256
	// MaxInteger is one past the largest version or segment length a header holds.
	MaxInteger = 1 << 53
)

// Count is how many frames n bytes of plaintext are cut into: ⌊n / S⌋ + 1.
func Count(n uint64) uint64 {
	return n/FrameSize + 1
}

// Length is the bytes of the frames n bytes of plaintext are cut into. n is below 2^63.
func Length(n uint64) uint64 {
	return n + Count(n)*Overhead
}

// Plaintext is the plaintext length and the frame count of a segment whose frames are length bytes. ok
// is false for a length no count of frames gives: one whose last frame would be shorter than Overhead.
func Plaintext(length uint64) (n, frames uint64, ok bool) {
	full, last := length/(FrameSize+Overhead), length%(FrameSize+Overhead)
	if last < Overhead {
		return 0, 0, false
	}
	return full*FrameSize + last - Overhead, full + 1, true
}

// Leaf is leaf_i: SHA-256(tuple("seald/v1/frame", frame_i)), over the frame's bytes as stored.
func Leaf(frame []byte) [LeafSize]byte {
	return taggedHash("seald/v1/frame", frame)
}

// Root is a segment's root: SHA-256(tuple("seald/v1/frames", frame list)).
func Root(list []byte) [LeafSize]byte {
	return taggedHash("seald/v1/frames", list)
}

// taggedHash is SHA-256(tuple(label, b)), hashed as laid out and never copied. A b of 2^32 bytes or
// more has no u32be length, and is a fault: it panics.
func taggedHash(label string, b []byte) [LeafSize]byte {
	if uint64(len(b)) > math.MaxUint32 {
		panic("layout: a tuple part of 2^32 bytes or more")
	}
	h := sha256.New()
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(label))) //nolint:gosec // a label is a constant of a few bytes
	h.Write(n[:])
	h.Write([]byte(label))
	binary.BigEndian.PutUint32(n[:], uint32(len(b))) //nolint:gosec // checked above
	h.Write(n[:])
	h.Write(b)
	return [LeafSize]byte(h.Sum(nil))
}

// Source is a container's bytes. An error from ReadAt is returned unchanged.
type Source interface {
	io.ReaderAt
	Size() int64
}

// Segment is a segment as the header names it, and where its frames and its frame list are.
type Segment struct {
	Name      string
	Length    uint64
	Plaintext uint64
	Frames    uint64
	Offset    int64
	List      int64
}

// Container is a container whose header, size and segments are its envelope's.
type Container struct {
	// Header is the header's bytes, which frame 0 of each segment binds.
	Header   []byte
	Locator  sealdcrypto.Locator
	Version  uint64
	Segments []Segment
}

// The refusals of reading a container, which open's tests match too.
var (
	ErrMalformedText   = refusal.New(sealdcrypto.RefusalKindMalformed, "text that is not well-formed Unicode")
	ErrEmptyLocator    = refusal.New(sealdcrypto.RefusalKindMalformed, "an empty locator")
	ErrShort           = refusal.New(sealdcrypto.RefusalKindMalformed, "a container shorter than its header")
	ErrBadHeader       = refusal.New(sealdcrypto.RefusalKindMalformed, "a header that does not parse")
	ErrOtherFormat     = refusal.New(sealdcrypto.RefusalKindUnsupported, "a container of a version v1 does not have")
	ErrFlagSet         = refusal.New(sealdcrypto.RefusalKindUnsupported, "a container with a flag set")
	ErrTooLarge        = refusal.New(sealdcrypto.RefusalKindOutOfRange, "a version or length of 2^53 or more")
	ErrTooManySegments = refusal.New(sealdcrypto.RefusalKindOutOfRange, "a header of more than 256 segments")
	ErrTwoSegments     = refusal.New(sealdcrypto.RefusalKindMalformed, "a header with two segments of one name")
	ErrNoFrameCount    = refusal.New(sealdcrypto.RefusalKindMalformed, "a segment length that no count of frames gives")
	ErrTooLong         = refusal.New(sealdcrypto.RefusalKindOutOfRange, "a segment of more frames than a frame list holds")
	ErrBadSize         = refusal.New(sealdcrypto.RefusalKindMalformed, "a container whose frame lists are not 32 bytes for each frame")
	ErrOtherEnvelope   = refusal.New(sealdcrypto.RefusalKindAuthenticationFailed, "a container that is not the one its envelope names")
	ErrOtherList       = refusal.New(sealdcrypto.RefusalKindAuthenticationFailed, "a frame list whose root is not the envelope's")
	ErrOtherFrame      = refusal.New(sealdcrypto.RefusalKindAuthenticationFailed, "a frame that is not its leaf")
)

// Open reads source's header alone and checks it against the envelope's locator, version and segment
// names, in the envelope's order. Caller text is checked before accessing source.
func Open(source Source, locator sealdcrypto.Locator, version uint64, names []string) (*Container, error) {
	if locator == "" {
		return nil, ErrEmptyLocator
	}
	if _, ok := encoding.Text(string(locator)); !ok {
		return nil, ErrMalformedText
	}
	for _, name := range names {
		if _, ok := encoding.Text(name); !ok {
			return nil, ErrMalformedText
		}
	}
	size := source.Size()
	if size < 4 {
		return nil, ErrShort
	}
	n, err := ReadAt(source, 0, 4)
	if err != nil {
		return nil, err
	}
	hl := uint64(binary.BigEndian.Uint32(n))
	if hl > uint64(size)-4 {
		return nil, ErrShort
	}
	header, err := ReadAt(source, 4, hl)
	if err != nil {
		return nil, err
	}
	h, err := parseHeader(header, uint64(size))
	if err != nil {
		return nil, err
	}
	if h.locator != locator || h.version != version || h.count != len(names) {
		return nil, ErrOtherEnvelope
	}
	// Only now is a segment held, as many as the envelope names.
	c := &Container{Header: header, Locator: h.locator, Version: h.version, Segments: make([]Segment, len(names))}
	at := 4 + hl
	rest := h.entries
	for i, want := range names {
		var e []byte
		e, rest, _ = encoding.Next(rest)
		name, length, _ := entryOf(e)
		if string(name) != want {
			return nil, ErrOtherEnvelope
		}
		n, frames, _ := Plaintext(length)
		c.Segments[i] = Segment{Name: want, Length: length, Plaintext: n, Frames: frames, Offset: int64(at)} //nolint:gosec // at is below size, an int64
		at += length
	}
	for i := range c.Segments {
		c.Segments[i].List = int64(at) //nolint:gosec // at is below size, an int64
		at += c.Segments[i].Frames * LeafSize
	}
	return c, nil
}

// FrameList reads segment i's frame list and checks it against root.
func (c *Container) FrameList(source Source, i int, root []byte) ([]byte, error) {
	s := &c.Segments[i]
	list, err := ReadAt(source, s.List, s.Frames*LeafSize)
	if err != nil {
		return nil, err
	}
	if r := Root(list); subtle.ConstantTimeCompare(r[:], root) != 1 {
		return nil, ErrOtherList
	}
	return list, nil
}

// Frame reads frame j of segment i into buf, which it grows where it is too short, and checks it
// against its leaf in list, the segment's checked frame list. No field of the frame is read before it
// matches its leaf.
func (c *Container) Frame(source Source, i int, list []byte, j uint64, buf []byte) ([]byte, error) {
	s := &c.Segments[i]
	n := uint64(FrameSize + Overhead)
	if j == s.Frames-1 {
		n = s.Length - j*n
	}
	f := slices.Grow(buf[:0], int(n))[:n]                                               //nolint:gosec // a frame is at most S + 24 bytes
	if err := readInto(source, s.Offset+int64(j*(FrameSize+Overhead)), f); err != nil { //nolint:gosec // below the segment's length
		return nil, err
	}
	if leaf := Leaf(f); subtle.ConstantTimeCompare(leaf[:], list[j*LeafSize:(j+1)*LeafSize]) != 1 {
		return nil, ErrOtherFrame
	}
	return f, nil
}

// Check checks each segment's frame list against its root and then each of its frames against its
// leaf, segment by segment in the header's order, and gives the first refusal. roots are the
// envelope's, in its order, which Open held to the header's.
func (c *Container) Check(source Source, roots [][]byte) error {
	if len(roots) != len(c.Segments) {
		panic("layout: a root for each segment")
	}
	buf := make([]byte, FrameSize+Overhead)
	for i := range c.Segments {
		list, err := c.FrameList(source, i, roots[i])
		if err != nil {
			return err
		}
		for j := range c.Segments[i].Frames {
			if buf, err = c.Frame(source, i, list, j, buf); err != nil {
				return err
			}
		}
	}
	return nil
}

// parsedHeader is an accepted header; entryOf reads each entry of entries.
type parsedHeader struct {
	locator sealdcrypto.Locator
	version uint64
	entries []byte
	count   int
}

// entryOf reads a header's entry in place; ok is false for an entry of another form.
func entryOf(e []byte) (name []byte, length uint64, ok bool) {
	name, rest, ok := encoding.Next(e)
	if !ok {
		return nil, 0, false
	}
	l, rest, ok := encoding.Next(rest)
	if !ok || len(rest) != 0 || len(l) != 8 {
		return nil, 0, false
	}
	return name, binary.BigEndian.Uint64(l), true
}

type span struct{ at, n uint32 }

// givenTwice sorts names, so it takes n log n time and holds nothing more.
func givenTwice(entries []byte, names []span) bool {
	text := func(s span) []byte { return entries[s.at : s.at+s.n] }
	slices.SortFunc(names, func(a, b span) int { return bytes.Compare(text(a), text(b)) })
	for i := 1; i < len(names); i++ {
		if bytes.Equal(text(names[i-1]), text(names[i])) {
			return true
		}
	}
	return false
}

// parseHeader checks the header in its one order, each part's form just before its value, and only then
// the container's size, so a header refused for itself is refused alike whatever the size.
//
// It reads the header in place, holding only where each entry's name is, 8 bytes per entry, so a header
// of MaxSegments entries costs no more than that.
func parseHeader(header []byte, size uint64) (*parsedHeader, error) {
	n, ok := encoding.Parses(header)
	if !ok || n != 5 {
		return nil, ErrBadHeader
	}
	parts, _ := encoding.ParseTuple(header)
	if string(parts[0]) != Label {
		if otherVersion(parts[0]) {
			return nil, ErrOtherFormat
		}
		return nil, ErrBadHeader
	}
	if len(parts[1]) != FlagsSize {
		return nil, ErrBadHeader
	}
	if parts[1][0]|parts[1][1] != 0 {
		return nil, ErrFlagSet
	}
	locator := string(parts[2])
	if _, ok := encoding.Text(locator); !ok {
		return nil, ErrMalformedText
	}
	if locator == "" {
		return nil, ErrEmptyLocator
	}
	if len(parts[3]) != 8 {
		return nil, ErrBadHeader
	}
	version := binary.BigEndian.Uint64(parts[3])
	if version >= MaxInteger {
		return nil, ErrTooLarge
	}
	count, ok := encoding.Parses(parts[4])
	if !ok {
		return nil, ErrBadHeader
	}
	// A 257th entry is refused before it is read, or any entry before it, so what reading a header costs
	// is bounded before anything is checked against its envelope.
	if count > MaxSegments {
		return nil, ErrTooManySegments
	}
	// A name given twice is found once the walk stops, at its end or at the first entry refused
	// otherwise, so a name given twice before it came before that refusal.
	names := make([]span, 0, count)
	var refused error
	for rest := parts[4]; len(rest) > 0; {
		at := len(parts[4]) - len(rest) + 8 // past the entry's length and its name's
		var e []byte
		e, rest, _ = encoding.Next(rest)
		name, length, ok := entryOf(e)
		if !ok {
			refused = ErrBadHeader
			break
		}
		if !encoding.WellFormed(name) {
			refused = ErrMalformedText
			break
		}
		names = append(names, span{uint32(at), uint32(len(name))}) //nolint:gosec // within a header, below 2^32
		if length >= MaxInteger {
			refused = ErrTooLarge
			break
		}
		_, frames, ok := Plaintext(length)
		if !ok {
			refused = ErrNoFrameCount
			break
		}
		if frames > MaxFrames {
			refused = ErrTooLong
			break
		}
	}
	if givenTwice(parts[4], names) {
		return nil, ErrTwoSegments
	}
	if refused != nil {
		return nil, refused
	}
	// Each frame list is below 2^32 bytes and the entries below 2^30, so the size does not overflow.
	at, lists := 4+uint64(len(header)), uint64(0)
	for rest := parts[4]; len(rest) > 0; {
		var e []byte
		e, rest, _ = encoding.Next(rest)
		_, length, _ := entryOf(e)
		if length > size-at {
			return nil, ErrBadSize
		}
		at += length
		_, frames, _ := Plaintext(length)
		lists += frames * LeafSize
	}
	if lists != size-at {
		return nil, ErrBadSize
	}
	return &parsedHeader{locator: sealdcrypto.Locator(locator), version: version, entries: parts[4], count: count}, nil
}

// otherVersion is whether label is seald/vN/container for a decimal N other than 1 with no leading zero:
// another version's container, unsupported rather than malformed.
func otherVersion(label []byte) bool {
	n, ok := bytes.CutPrefix(label, []byte("seald/v"))
	if !ok {
		return false
	}
	if n, ok = bytes.CutSuffix(n, []byte("/container")); !ok || len(n) == 0 || (n[0] == '0' && len(n) > 1) || string(n) == "1" {
		return false
	}
	for _, c := range n {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ReadAt is n bytes of source from off, in a new slice.
func ReadAt(source Source, off int64, n uint64) ([]byte, error) {
	b := make([]byte, n)
	if err := readInto(source, off, b); err != nil {
		return nil, err
	}
	return b, nil
}

func readInto(source Source, off int64, b []byte) error {
	m, err := source.ReadAt(b, off)
	if m == len(b) {
		return nil
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return err
}

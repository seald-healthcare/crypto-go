package open

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"math"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/canonical"
	"github.com/seald-healthcare/crypto-go/internal/encoding"
	"github.com/seald-healthcare/crypto-go/internal/frame"
	"github.com/seald-healthcare/crypto-go/internal/layout"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
)

const (
	// ContentKeySize is a content key's size.
	ContentKeySize = frame.ContentKeySize
	// CommitmentSize is a key commitment's size, and RootSize a root's.
	CommitmentSize = 32
	RootSize       = layout.LeafSize

	body = "body"
)

// NewContentKey returns a fresh content key for one segment of one version. Never reuse one; zeroise it
// once it is wrapped.
func NewContentKey() []byte {
	return Random(ContentKeySize)
}

// SegmentCommitment is a segment's root and key commitment, as its envelope carries them. Neither is
// secret.
type SegmentCommitment struct {
	Segment string
	// Root is the root of the segment's frame list.
	Root       []byte
	Commitment []byte
}

// ContainerInput is a new version's container: the body and its fields, each under a fresh content key.
type ContainerInput struct {
	Tenant  sealdcrypto.TenantID
	Locator sealdcrypto.Locator
	Version uint64
	Body    ContainerInputBody
	Fields  []ContainerInputField
}

// ContainerInputBody is the body. Metadata's size, where it has one, must be Length. Content is read to
// exactly Length bytes: bytes.NewReader(b) and len(b) for content in memory.
type ContainerInputBody struct {
	Key      []byte
	Metadata sealdcrypto.JSON
	Content  io.Reader
	Length   int
}

// ContainerInputField is a field released alone, its value written as canonical JSON.
type ContainerInputField struct {
	Segment string
	Key     []byte
	Value   sealdcrypto.JSON
}

// MaxSegments is the most segments a container holds, and MaxFields the most fields beside its body.
const (
	MaxSegments = layout.MaxSegments
	MaxFields   = MaxSegments - 1
)

var (
	// errContentLong is the error SealContainer returns for a content longer than its length. A content
	// shorter than its length is io.ErrUnexpectedEOF.
	errContentLong = errors.New("sealContainer: a content longer than its length")
)

type sealing struct {
	name      string
	key       []byte
	plaintext io.Reader
	n         uint64
}

// SealContainer writes input's container to w and returns each segment's commitment, in header order,
// for the envelope the writer signs. An error from w or Content is returned unchanged; past the header
// it leaves part of a container in w, which the caller discards.
//
// Every input is the caller's own, so a bad one is a fault, never a refusal: a content key that is not
// 32 bytes, checked first, one key for two segments, compared in constant time, and a metadata or field
// that has no canonical JSON among them.
func SealContainer(w io.Writer, input ContainerInput) ([]SegmentCommitment, error) {
	b := input.Body
	checkContentKey("sealContainer", b.Key)
	for _, f := range input.Fields {
		checkContentKey("sealContainer", f.Key)
	}
	if b.Content == nil {
		panic("sealContainer: no content")
	}
	if b.Length < 0 {
		panic("sealContainer: a negative length")
	}
	if len(input.Fields) > MaxFields {
		panic("sealContainer: more than 255 fields")
	}
	if input.Version >= layout.MaxInteger {
		panic("sealContainer: a version of 2^53 or more")
	}
	locator := sealedLocator("sealContainer", input.Locator)
	m, err := canonical.JSON(b.Metadata)
	if err != nil {
		panic("sealContainer: metadata with no canonical JSON")
	}
	defer clear(m)
	if read, err := canonical.ParseJSON(m); err != nil || !sizeIs(read, uint64(b.Length)) {
		panic("sealContainer: a content whose length is not the metadata's size")
	}
	metadata := encoding.Tuple(m)
	defer clear(metadata)
	if len(metadata) > layout.FrameSize {
		panic("sealContainer: metadata longer than frame 0")
	}
	segments := []sealing{{
		name:      body,
		key:       b.Key,
		plaintext: io.MultiReader(bytes.NewReader(metadata), io.LimitReader(b.Content, int64(b.Length))),
		n:         uint64(len(metadata)) + uint64(b.Length),
	}}
	for _, f := range input.Fields {
		value, err := canonical.JSON(f.Value)
		if err != nil {
			panic("sealContainer: a field's value with no canonical JSON")
		}
		defer clear(value)
		segments = append(segments, sealing{name: f.Segment, key: f.Key, plaintext: bytes.NewReader(value), n: uint64(len(value))})
	}
	return sealSegments(w, "sealContainer", input.Tenant, input.Locator, locator, input.Version, segments, func() error { return atItsEnd(b.Content) })
}

// sealSegments writes the header, every segment's frames, then every frame list. afterBody, where it is
// not nil, runs once the body's frames are written, and its error ends the container.
func sealSegments(w io.Writer, op string, tenant sealdcrypto.TenantID, loc sealdcrypto.Locator, locator []byte, version uint64, segments []sealing, afterBody func() error) ([]SegmentCommitment, error) {
	var ok bool
	names := make([][]byte, len(segments))
	for i, s := range segments {
		checkContentKey(op, s.key)
		for _, t := range segments[:i] {
			if s.name == t.name {
				panic(op + ": two segments of one name")
			}
			if subtle.ConstantTimeCompare(s.key, t.key) == 1 {
				panic(op + ": one content key for two segments")
			}
		}
		if names[i], ok = encoding.Text(s.name); !ok {
			panic(op + ": a field's name that is not well-formed Unicode")
		}
		if layout.Count(s.n) > layout.MaxFrames {
			panic(op + ": a segment of 2^27 frames or more")
		}
	}

	entries := make([][]byte, len(segments))
	for i, s := range segments {
		entries[i] = encoding.Tuple(names[i], encoding.U64(layout.Length(s.n)))
	}
	header := encoding.Tuple([]byte(layout.Label), make([]byte, layout.FlagsSize), locator, encoding.U64(version), encoding.Tuple(entries...))
	if _, err := w.Write(encoding.Tuple(header)); err != nil {
		return nil, err
	}

	commitments := make([]SegmentCommitment, len(segments))
	lists := make([][]byte, len(segments))
	buf := make([]byte, layout.FrameSize)
	defer clear(buf)
	for j, s := range segments {
		keys, err := frame.SegmentKeys(s.key, tenant, loc, version, s.name)
		if err != nil {
			return nil, err
		}
		frames := layout.Count(s.n)
		list := make([]byte, 0, frames*layout.LeafSize)
		for i := range frames {
			m := min(s.n-i*layout.FrameSize, layout.FrameSize)
			if _, err := io.ReadFull(s.plaintext, buf[:m]); err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return nil, err
			}
			f := keys.Seal(i, i == frames-1, header, buf[:m])
			leaf := layout.Leaf(f)
			list = append(list, leaf[:]...)
			if _, err := w.Write(f); err != nil {
				return nil, err
			}
		}
		if j == 0 && afterBody != nil {
			if err := afterBody(); err != nil {
				return nil, err
			}
		}
		lists[j] = list
		root := layout.Root(list)
		commitments[j] = SegmentCommitment{
			Segment:    s.name,
			Root:       root[:],
			Commitment: commitment(s.key, tenant, locator, version, names[j]),
		}
	}
	for _, list := range lists {
		if _, err := w.Write(list); err != nil {
			return nil, err
		}
	}
	return commitments, nil
}

func atItsEnd(content io.Reader) error {
	var one [1]byte
	n, err := io.ReadFull(content, one[:])
	clear(one[:])
	switch {
	case n == 1:
		return errContentLong
	case err == io.EOF:
		return nil
	default:
		return err
	}
}

// commitment is the segment's key commitment. HKDF takes a key of any length, so a key that is not 32
// bytes is checked here, as a fault.
func commitment(key []byte, tenant sealdcrypto.TenantID, locator []byte, version uint64, segment []byte) []byte {
	checkContentKey("commitment", key)
	if len(locator) == 0 {
		panic("commitment: an empty locator")
	}
	return encoding.HKDF(key, "seald/v1/key-commitment", CommitmentSize, encoding.UUID(tenant), locator, encoding.U64(version), segment)
}

// checkContentKey faults on a content key that is not 32 bytes, before every other check, so no refusal
// stands in its place. An unwrapped key is always 32 bytes, so any other is the caller's mistake.
func checkContentKey(op string, key []byte) {
	if len(key) != ContentKeySize {
		panic(op + ": a content key that is not 32 bytes")
	}
}

// ContainerSource is a container's bytes: *bytes.Reader in memory, *io.SectionReader over a file, or
// ranged reads of the caller's. An error from ReadAt is returned unchanged.
type ContainerSource interface {
	io.ReaderAt
	Size() int64
}

// OpenContainerExpected is the envelope the reader verified, never read from the container.
type OpenContainerExpected struct {
	Tenant   sealdcrypto.TenantID
	Locator  sealdcrypto.Locator
	Version  uint64
	Segments []SegmentCommitment
}

// OpenedContainerSegment is a segment as the header names it.
type OpenedContainerSegment struct {
	Segment string
	Length  int64
}

// OpenedContainer is a container whose header is checked against its envelope. Each read checks the key,
// the frame list and each frame it reads before it opens a frame.
type OpenedContainer struct {
	source      ContainerSource
	tenant      sealdcrypto.TenantID
	c           *layout.Container
	roots       [][]byte
	commitments [][]byte
}

// OpenContainer reads source's header alone and checks it against expected, the envelope the reader
// verified. The envelope's text is checked before any byte of the container, and the header's
// checks come before its size. An error from source is returned unchanged.
func OpenContainer(source ContainerSource, expected OpenContainerExpected) (*OpenedContainer, error) {
	if source == nil {
		panic("openContainer: no source")
	}
	names := make([]string, len(expected.Segments))
	for i, s := range expected.Segments {
		names[i] = s.Segment
	}
	c, err := layout.Open(source, expected.Locator, expected.Version, names)
	if err != nil {
		return nil, err
	}
	o := &OpenedContainer{source: source, tenant: expected.Tenant, c: c}
	for _, s := range expected.Segments {
		o.roots = append(o.roots, bytes.Clone(s.Root))
		o.commitments = append(o.commitments, bytes.Clone(s.Commitment))
	}
	return o, nil
}

// sealedLocator is loc as a tuple carries it, or a fault of op's where a reader would refuse it.
func sealedLocator(op string, loc sealdcrypto.Locator) []byte {
	if loc == "" {
		panic(op + ": an empty locator")
	}
	locator, ok := encoding.Text(string(loc))
	if !ok {
		panic(op + ": a locator that is not well-formed Unicode")
	}
	return locator
}

// Locator is the container's locator.
func (c *OpenedContainer) Locator() sealdcrypto.Locator { return c.c.Locator }

// Version is the container's version.
func (c *OpenedContainer) Version() uint64 { return c.c.Version }

// Segments is each segment, in the header's order.
func (c *OpenedContainer) Segments() []OpenedContainerSegment {
	out := make([]OpenedContainerSegment, len(c.c.Segments))
	for i, s := range c.c.Segments {
		out[i] = OpenedContainerSegment{Segment: s.Name, Length: int64(s.Length)} //nolint:gosec // length is below 2^53, step 1 checked
	}
	return out
}

var (
	otherKey     = refusal.New(sealdcrypto.RefusalKindAuthenticationFailed, "a content key whose commitment is not the envelope's")
	longMetadata = refusal.New(sealdcrypto.RefusalKindMalformed, "metadata that runs past frame 0")
	otherSize    = refusal.New(sealdcrypto.RefusalKindMalformed, "metadata whose size is not the content's length")
)

type reading struct {
	c    *OpenedContainer
	i    int
	s    *layout.Segment
	keys *frame.Keys
	list []byte
}

// read checks key's commitment, then the frame list's root. A key that is not 32 bytes, then a segment
// the container does not have, are faults.
func (c *OpenedContainer) read(op, name string, key []byte) (*reading, error) {
	checkContentKey(op, key)
	i := c.find(op, name)
	if subtle.ConstantTimeCompare(commitment(key, c.tenant, []byte(c.c.Locator), c.c.Version, []byte(name)), c.commitments[i]) != 1 {
		return nil, otherKey
	}
	list, err := c.c.FrameList(c.source, i, c.roots[i])
	if err != nil {
		return nil, err
	}
	keys, err := frame.SegmentKeys(key, c.tenant, c.c.Locator, c.c.Version, name)
	if err != nil {
		return nil, err
	}
	return &reading{c: c, i: i, s: &c.c.Segments[i], keys: keys, list: list}, nil
}

func (r *reading) frame(i uint64) ([]byte, error) {
	f, err := r.c.c.Frame(r.c.source, r.i, r.list, i, nil)
	if err != nil {
		return nil, err
	}
	return r.keys.Open(i, i == r.s.Frames-1, r.c.c.Header, f)
}

// metadataOf refuses a metadata whose size is not the content's length, so every read refuses such a
// frame 0 alike, and a range within the metadata's size is always within the content.
func metadataOf(p0 []byte, n uint64) (sealdcrypto.JSON, uint64, error) {
	if len(p0) < 4 {
		return nil, 0, longMetadata
	}
	end := 4 + uint64(binary.BigEndian.Uint32(p0))
	if end > uint64(len(p0)) {
		return nil, 0, longMetadata
	}
	m, err := canonical.ParseJSON(p0[4:end])
	if err != nil {
		return nil, 0, err
	}
	if !sizeIs(m, n-end) {
		return nil, 0, otherSize
	}
	return m, end, nil
}

// sizeIs is whether m's size, where it has one, is length. A metadata with no size gives none to check.
func sizeIs(m sealdcrypto.JSON, length uint64) bool {
	o, ok := m.(map[string]any)
	if !ok {
		return true
	}
	size, ok := o["size"]
	if !ok {
		return true
	}
	n, ok := size.(int64)
	return ok && n >= 0 && uint64(n) == length
}

// Metadata returns the body's metadata, reading frame 0 alone. bodyKey is never kept. A key that is not
// 32 bytes, then a container with no body, are faults.
func (c *OpenedContainer) Metadata(bodyKey []byte) (sealdcrypto.JSON, error) {
	r, err := c.read("metadata", body, bodyKey)
	if err != nil {
		return nil, err
	}
	p, err := r.frame(0)
	if err != nil {
		return nil, err
	}
	defer clear(p)
	m, _, err := metadataOf(p, r.s.Plaintext)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// ContentRange is Length bytes of the content from Offset.
type ContentRange struct {
	Offset int64
	Length int64
}

// ContentLength returns the content's length, reading frame 0 alone; ask Content for a range within it.
// It is an int64, since an int on a 32-bit platform holds less than a container may. It faults as
// Metadata does.
func (c *OpenedContainer) ContentLength(bodyKey []byte) (int64, error) {
	r, err := c.read("contentLength", body, bodyKey)
	if err != nil {
		return 0, err
	}
	p, err := r.frame(0)
	if err != nil {
		return 0, err
	}
	defer clear(p)
	_, start, err := metadataOf(p, r.s.Plaintext)
	if err != nil {
		return 0, err
	}
	return int64(r.s.Plaintext - start), nil //nolint:gosec // below 2^53, step 1 checked
}

// Content returns the body's content, or the range of it rng names, reading only the frames it needs,
// in a new slice for the caller to zeroise. A nil rng is the whole content.
//
// A key that is not 32 bytes is a fault before any other check. A container with no body, a negative
// range, or one past the body's plaintext are faults once the container is opened, and a range past
// the content once frame 0 is checked. Read a content longer than a slice holds with ContentStream.
func (c *OpenedContainer) Content(bodyKey []byte, rng *ContentRange) ([]byte, error) {
	checkContentKey("content", bodyKey)
	if rng != nil && (rng.Offset < 0 || rng.Length < 0) {
		panic("content: a negative offset or length")
	}
	if s := c.c.Segments[c.find("content", body)]; rng != nil {
		off, n := uint64(rng.Offset), uint64(rng.Length) //nolint:gosec // neither is negative, checked above
		if off > s.Plaintext || n > s.Plaintext-off {
			panic("content: a range past the body's plaintext")
		}
	}
	r, err := c.read("content", body, bodyKey)
	if err != nil {
		return nil, err
	}
	p0, err := r.frame(0)
	if err != nil {
		return nil, err
	}
	defer clear(p0)
	_, start, err := metadataOf(p0, r.s.Plaintext)
	if err != nil {
		return nil, err
	}
	end := r.s.Plaintext
	if rng != nil {
		off, n := uint64(rng.Offset), uint64(rng.Length) //nolint:gosec // neither is negative, checked above
		if off > end-start || n > end-start-off {
			panic("content: a range outside the content")
		}
		start, end = start+off, start+off+n
	}
	if end-start > math.MaxInt {
		panic("content: a content or range longer than a slice holds")
	}
	out := make([]byte, 0, end-start)
	if start == end {
		return out, nil
	}
	for i := start / layout.FrameSize; i <= (end-1)/layout.FrameSize; i++ {
		p := p0
		if i > 0 {
			if p, err = r.frame(i); err != nil {
				clear(out)
				return nil, err
			}
		}
		at := i * layout.FrameSize
		out = append(out, p[max(start, at)-at:min(end, at+uint64(len(p)))-at]...)
		if i > 0 {
			clear(p)
		}
	}
	return out, nil
}

// ContentStream returns the body's content as a stream, once the key and the frame list are checked.
// It gives each frame's plaintext only once the frame is checked, and ends with the first refusal, so a
// stream that ends without an error gave the whole content in order. It faults as Metadata does.
func (c *OpenedContainer) ContentStream(bodyKey []byte) (io.Reader, error) {
	r, err := c.read("contentStream", body, bodyKey)
	if err != nil {
		return nil, err
	}
	return &contentStream{r: r}, nil
}

// find is the index of the segment named name; one the container does not have is a fault.
func (c *OpenedContainer) find(op, name string) int {
	for i := range c.c.Segments {
		if c.c.Segments[i].Name == name {
			return i
		}
	}
	panic(op + ": a segment the container does not have")
}

type contentStream struct {
	r    *reading
	next uint64
	skip uint64
	buf  []byte
	p    []byte
	err  error
}

func (s *contentStream) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for len(s.buf) == 0 {
		if s.err != nil {
			return 0, s.err
		}
		s.err = s.fill()
	}
	n := copy(b, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

func (s *contentStream) fill() error {
	clear(s.p)
	if s.next == s.r.s.Frames {
		return io.EOF
	}
	p, err := s.r.frame(s.next)
	if err != nil {
		return err
	}
	if s.next == 0 {
		if _, s.skip, err = metadataOf(p, s.r.s.Plaintext); err != nil {
			clear(p)
			return err
		}
	}
	s.next++
	d := min(s.skip, uint64(len(p)))
	s.skip -= d
	s.p, s.buf = p, p[d:]
	return nil
}

// Field returns the value of the field released alone as segment, under key, which is never kept. A
// key that is not 32 bytes, checked first, a segment the container does not have, and the body, are
// faults.
func (c *OpenedContainer) Field(segment string, key []byte) (sealdcrypto.JSON, error) {
	checkContentKey("field", key)
	if segment == body {
		panic("field: the body, which is not a field")
	}
	r, err := c.read("field", segment, key)
	if err != nil {
		return nil, err
	}
	value := make([]byte, 0, r.s.Plaintext)
	defer func() { clear(value) }()
	for i := range r.s.Frames {
		p, err := r.frame(i)
		if err != nil {
			return nil, err
		}
		value = append(value, p...)
		clear(p)
	}
	return canonical.ParseJSON(value)
}

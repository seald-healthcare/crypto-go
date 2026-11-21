package verify

import (
	"io"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/layout"
)

// ContainerSource is a container's bytes: *bytes.Reader in memory, *io.SectionReader over a file, or
// ranged reads of the caller's. An error from ReadAt is returned unchanged.
type ContainerSource interface {
	io.ReaderAt
	Size() int64
}

// SegmentRoot is a segment's name and the root of its frame list, as its envelope carries them.
type SegmentRoot struct {
	Segment string
	Root    []byte
}

// CheckContainerExpected is what CheckContainer reads of a container's envelope: its locator, its
// version, and each segment's root, in the envelope's order.
type CheckContainerExpected struct {
	Locator  sealdcrypto.Locator
	Version  uint64
	Segments []SegmentRoot
}

// CheckedContainerSegment is a segment as the header names it, with its frames' length.
type CheckedContainerSegment struct {
	Segment string
	Length  int64
}

// CheckContainerResult is a checked container's locator, version and segments, in the header's order.
type CheckContainerResult struct {
	Locator  sealdcrypto.Locator
	Version  uint64
	Segments []CheckedContainerSegment
}

// CheckContainer checks a whole container against its envelope with no key: its header, its size and
// its segments are the envelope's, each segment's frame list is its root, and every frame is its leaf.
// It reads every byte of the container once and decrypts nothing. It gives the first refusal, and an
// error from source unchanged.
//
// It proves the container is the one the envelope commits to, never that the envelope is genuine or
// that a content key opens it: verify the envelope's signature where that matters.
func CheckContainer(source ContainerSource, expected CheckContainerExpected) (CheckContainerResult, error) {
	if source == nil {
		panic("checkContainer: no source")
	}
	names := make([]string, len(expected.Segments))
	roots := make([][]byte, len(expected.Segments))
	for i, s := range expected.Segments {
		names[i], roots[i] = s.Segment, s.Root
	}
	c, err := layout.Open(source, expected.Locator, expected.Version, names)
	if err != nil {
		return CheckContainerResult{}, err
	}
	if err := c.Check(source, roots); err != nil {
		return CheckContainerResult{}, err
	}
	r := CheckContainerResult{Locator: c.Locator, Version: c.Version, Segments: make([]CheckedContainerSegment, len(c.Segments))}
	for i, s := range c.Segments {
		r.Segments[i] = CheckedContainerSegment{Segment: s.Name, Length: int64(s.Length)} //nolint:gosec // below 2^53, the header checked
	}
	return r, nil
}

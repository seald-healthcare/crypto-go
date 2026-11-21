package open

import (
	"bytes"
	"io"
	"math"
	"slices"

	sealdcrypto "github.com/seald-healthcare/crypto-go"
	"github.com/seald-healthcare/crypto-go/internal/canonical"
	"github.com/seald-healthcare/crypto-go/internal/encoding"
	"github.com/seald-healthcare/crypto-go/internal/layout"
	"github.com/seald-healthcare/crypto-go/internal/refusal"
)

// The folder index and the pre-image journal are containers of their own (the Crypto API, Container),
// each of one segment, body, whose plaintext is its canonical JSON alone, with no metadata before it,
// and neither compressed before it is encrypted.

const (
	// IndexFormat is the format of a folder index a writer writes. ReadFolderIndex also reads format 2,
	// which is format 3 without name, and format 1, which is format 2 without hidden.
	IndexFormat = 3
	// MaxIndexEntries is the most entries a folder index holds. A larger set is divided into key
	// domains.
	MaxIndexEntries = 20000
	// JournalVersion is the version a pre-image journal's envelope names.
	JournalVersion = 1
	// MaxJournalSaves is the most saves a pre-image journal holds, one for each save its commit lease
	// names.
	MaxJournalSaves = 100
)

// FolderIndexInput is what a key domain's folder index is sealed from: its tenant, the domain root's
// locator, which the index is stored under, the index's version, the body's content key, fresh from
// NewContentKey, and the index's body, {"format": 3, "name": …, "entries": […]}, its name where it has
// one, as a JSON value.
type FolderIndexInput struct {
	Tenant sealdcrypto.TenantID
	// Root is the domain root's locator.
	Root sealdcrypto.Locator
	// Version is the index's version, below 2^53.
	Version uint64
	Key     []byte
	Body    sealdcrypto.JSON
}

// JournalInput is what a pre-image journal is sealed from: its tenant, the commit lease it is stored
// under, whose locator journal/{lease_id} its envelope names, at version 1, the body's content key,
// fresh from NewContentKey, and the journal's body, {"saves": [{"envelope": …, "entry": …}, …]}, one
// item for each save the lease names, in its order, as a JSON value. A rewrite of the index alone, a
// mark among them, stores no journal.
type JournalInput struct {
	Tenant sealdcrypto.TenantID
	Lease  sealdcrypto.UUID
	Key    []byte
	Body   sealdcrypto.JSON
}

// JournalLocator is the locator of the pre-image journal stored under lease: journal/{lease_id}, the
// lease's id as RFC 9562's text in lower case, so journal/ followed by 36 characters. A journal's
// envelope names it, at version 1, so no journal shares a content key's wrap context with an index or
// another journal. SealJournal seals under it alone, and takes no locator, so no journal is sealed
// under any other, which the Crypto API, Container, makes a fault.
func JournalLocator(lease sealdcrypto.UUID) sealdcrypto.Locator {
	return sealdcrypto.Locator("journal/" + lease.String())
}

// SealFolderIndex is the vectors' sealContainer of a folder index: it writes the index's container to
// w, one segment, body, whose plaintext is the body's canonical JSON alone, and returns the body's
// commitment for the envelope the writer signs. It refuses nothing, since every input is the caller's
// own, and an error w returns is returned unchanged. Past the header, an error leaves w with part of a
// container, which the caller discards.
//
// Writing an index a reader refuses is a fault, so the body is read back as ReadFolderIndex reads it
// before anything is written, and one it refuses panics: a format other than 1, 2 or 3, a name in
// format 1 or 2 or one that is not non-empty text, more than MaxIndexEntries entries, an entry out of the table's form, a hidden in format 1 among them, and two
// entries sharing a path and name or a locator, an entry whose locator is empty, and index_fields of no
// field. A body with no canonical JSON, a root that is empty or not well-formed Unicode, a version of
// 2^53 or more, and a body of 2^27 frames or more are faults too, and panic. A key that is not 32 bytes
// is a fault before every other, whatever the body, as the Crypto API, Content, sets. The key is never
// kept.
func SealFolderIndex(w io.Writer, input FolderIndexInput) (SegmentCommitment, error) {
	const op = "sealFolderIndex"
	checkContentKey(op, input.Key)
	plaintext := jsonPlaintext(op, input.Body)
	defer clear(plaintext)
	v, _ := canonical.ParseJSON(plaintext)
	if _, err := indexOf(v); err != nil {
		panic(op + ": an index a reader refuses")
	}
	return sealJSON(w, op, input.Tenant, input.Root, input.Version, input.Key, plaintext)
}

// SealJournal is the vectors' sealContainer of a pre-image journal: it writes the journal's container
// to w, one segment, body, whose plaintext is the body's canonical JSON alone, under the locator
// JournalLocator(input.Lease) and version 1, and returns the body's commitment for the envelope the
// writer signs. It refuses nothing, and an error w returns is returned unchanged.
//
// The body is read back as ReadJournal reads it before anything is written, and one it refuses panics,
// so no journal is sealed that its reader refuses: an object of other members than saves, no save or
// more than MaxJournalSaves, a save of other members than envelope and entry, an envelope that is not
// an object, and an entry out of the folder index's table. A body with no canonical JSON, and a body
// of 2^27 frames or more, are faults too, and panic. A key that is not 32 bytes is a fault before
// every other, whatever the body, as the Crypto API, Content, sets. The key is never kept.
func SealJournal(w io.Writer, input JournalInput) (SegmentCommitment, error) {
	const op = "sealJournal"
	checkContentKey(op, input.Key)
	plaintext := jsonPlaintext(op, input.Body)
	defer clear(plaintext)
	v, _ := canonical.ParseJSON(plaintext)
	if _, err := journalOf(v); err != nil {
		panic(op + ": a journal a reader refuses")
	}
	return sealJSON(w, op, input.Tenant, JournalLocator(input.Lease), JournalVersion, input.Key, plaintext)
}

// jsonPlaintext is body's canonical JSON, the plaintext of a container of JSON alone, which a body with
// none makes a fault of op's.
func jsonPlaintext(op string, body sealdcrypto.JSON) []byte {
	b, err := canonical.JSON(body)
	if err != nil {
		panic(op + ": a body with no canonical JSON")
	}
	return b
}

// sealJSON writes the container of one segment, body, whose plaintext is plaintext alone.
func sealJSON(w io.Writer, op string, tenant sealdcrypto.TenantID, loc sealdcrypto.Locator, version uint64, key, plaintext []byte) (SegmentCommitment, error) {
	if version >= layout.MaxInteger {
		panic(op + ": a version of 2^53 or more")
	}
	locator := sealedLocator(op, loc)
	segments := []sealing{{name: body, key: key, plaintext: bytes.NewReader(plaintext), n: uint64(len(plaintext))}}
	commitments, err := sealSegments(w, op, tenant, loc, locator, version, segments, nil)
	if err != nil {
		return SegmentCommitment{}, err
	}
	return commitments[0], nil
}

// FolderIndex is a folder index's body as ReadFolderIndex reads it: its format, 1, 2 or 3, its name in
// format 3 where it has one, and its entries,
// in the order the body holds them, each an object of exactly the members its kind has, as the Crypto
// API's Container table sets, checked, and no two sharing a path and name or a locator.
type FolderIndex struct {
	// Format is the body's format, 1, 2 or 3. Format 1 holds no hidden, and only format 3 a name.
	Format int
	// Name is the key domain's own name, non-empty text, or "" where the index holds none: in format 1
	// or 2, and in format 3 before a client has written it, a dataset's root among them.
	Name string
	// Entries are the entries as the body writes them, each a map[string]any. A member whose form the
	// table leaves unchecked, such as type, created_at and modified_at, as text, and each value of
	// index_fields, is given as written, for the caller to read as the dataset sets. An entry whose
	// hidden is set is one a client leaves out of a listing until its person reveals it.
	Entries []sealdcrypto.JSON
}

// Journal is a pre-image journal's body as ReadJournal reads it.
type Journal struct {
	// Saves are the saves the commit lease names, 1 to MaxJournalSaves, in the lease's order.
	Saves []JournalSave
}

// JournalSave is one save of a pre-image journal: the version it saves and the index entry for it.
type JournalSave struct {
	// Envelope is the version's envelope as written, an object. It is read for its form alone: the
	// caller verifies it as it verifies every envelope before it commits it, since a journal holds
	// neither its writer's card nor its epoch.
	Envelope sealdcrypto.JSON
	// Entry is the index entry the writer was about to write, an object of exactly the members its
	// kind has, hidden among them, as a folder index's entries are.
	Entry sealdcrypto.JSON
}

var (
	notOneBody   = refusal.New(sealdcrypto.RefusalKindMalformed, "a container of other segments than body alone")
	noIndex      = refusal.New(sealdcrypto.RefusalKindMalformed, "a folder index that is not an object with a format")
	otherIndex   = refusal.New(sealdcrypto.RefusalKindUnsupported, "a folder index of a format this library does not know")
	notAnIndex   = refusal.New(sealdcrypto.RefusalKindMalformed, "a folder index of other members than format, entries and, in format 3, a name")
	manyEntries  = refusal.New(sealdcrypto.RefusalKindOutOfRange, "a folder index of more than 20000 entries")
	notAnEntry   = refusal.New(sealdcrypto.RefusalKindMalformed, "an index entry out of its form")
	sharedPlace  = refusal.New(sealdcrypto.RefusalKindMalformed, "two index entries sharing a path and name")
	sharedLocate = refusal.New(sealdcrypto.RefusalKindMalformed, "two index entries sharing a locator")
	notAJournal  = refusal.New(sealdcrypto.RefusalKindMalformed, "a pre-image journal out of its form")
	manySaves    = refusal.New(sealdcrypto.RefusalKindOutOfRange, "a pre-image journal of more than 100 saves")
	otherLease   = refusal.New(sealdcrypto.RefusalKindAuthenticationFailed, "a pre-image journal of another lease or another version")
	longBody     = refusal.New(sealdcrypto.RefusalKindOutOfRange, "a body longer than a slice holds on this platform")
)

// ReadFolderIndex is the vectors' folderIndex: the folder index source holds, opened against expected,
// the envelope the reader verified, as OpenContainer opens every container, its envelope's locator
// first, before any byte, then checked in the Crypto API's one order for an index, so an index that
// fails two checks gets one refusal:
//
//  1. malformed a container of other segments than body alone, before any frame is decrypted;
//  2. the body read whole under bodyKey, each read's checks first, its key's commitment, its frame list
//     and each frame, authentication-failed; then malformed a body that is not a canonical JSON object
//     with a format, unsupported a format that is another integer than 1, 2 or 3, and malformed one
//     that is no integer, before any other member is read;
//  3. malformed a body of other members than format and entries, and in format 3 a name where it has
//     one, non-empty text, or whose entries are not an array; only then out-of-range a 20,001st entry,
//     before any entry is read;
//  4. malformed each entry in turn that is not an object of exactly the members its kind has, each in
//     its form, a locator non-empty text, index_fields an object of at least one field, and hidden
//     import-records on a domain or import-record on a file, never in format 1, among them;
//  5. malformed two entries that share a path and name, or a locator.
//
// A reader never rewrites an index of a format it does not know, which is why it is refused unsupported
// and not malformed. An error source returns is returned unchanged. A key that is not 32 bytes, and
// then a nil source, are faults, and panic before any check, since a fault is raised whatever the input:
// the key's before any other fault of the read, as each read of a container raises it. bodyKey is never
// kept.
func ReadFolderIndex(source ContainerSource, expected OpenContainerExpected, bodyKey []byte) (FolderIndex, error) {
	checkContentKey("readFolderIndex", bodyKey)
	if source == nil {
		panic("readFolderIndex: no source")
	}
	c, err := OpenContainer(source, expected)
	if err != nil {
		return FolderIndex{}, err
	}
	v, err := c.jsonBody("readFolderIndex", bodyKey)
	if err != nil {
		return FolderIndex{}, err
	}
	return indexOf(v)
}

// ReadJournal is the vectors' journal: the pre-image journal source holds, which a client finishing a
// commit reads, opened against expected, the envelope the reader verified, and lease, the commit lease
// it came with, checked in the Crypto API's one order for a journal:
//
//  1. authentication-failed an envelope whose locator is not JournalLocator(lease), an empty one and one
//     that is not well-formed Unicode among them, or whose version is not 1, before every other check of
//     the envelope and before any byte of the container is read, so no frame is decrypted, a lease has
//     one journal, and the server cannot hand one writer another lease's journal or another version of
//     its own;
//  2. the container opened against the envelope as OpenContainer opens every container, and what it
//     refuses;
//  3. malformed a container of other segments than body alone;
//  4. the body read whole under bodyKey, each read's checks first, authentication-failed; then malformed
//     a body that is not a canonical JSON object of exactly saves, an array; then out-of-range a
//     save past MaxJournalSaves, before any save is read; then malformed no save, and each save in
//     turn that is not an object of exactly envelope, an object, and entry, an entry as the folder
//     index's table sets, hidden among its members.
//
// Each save is read alone, and no save is checked against another: two saves of one locator, or of one
// path and name, read, and the index the commit writes is checked when it is next read.
//
// lease is a UUID, which the caller reads from the text it is given with sealdcrypto.ParseUUID before
// it calls ReadJournal, so a lease id in another form is refused malformed before any check of the
// journal, as the Crypto API's Refusals sets for a caller's own input.
//
// Each envelope is given as written, and the caller verifies it as it verifies every envelope before it
// commits it. An error source returns is returned unchanged. A key that is not 32 bytes, and then a nil
// source, are faults, and panic before any check, since a fault is raised whatever the input: the key's
// before any other fault of the read, as each read of a container raises it. bodyKey is never kept.
func ReadJournal(source ContainerSource, expected OpenContainerExpected, lease sealdcrypto.UUID, bodyKey []byte) (Journal, error) {
	checkContentKey("readJournal", bodyKey)
	if source == nil {
		panic("readJournal: no source")
	}
	if expected.Locator != JournalLocator(lease) || expected.Version != JournalVersion {
		return Journal{}, otherLease
	}
	c, err := OpenContainer(source, expected)
	if err != nil {
		return Journal{}, err
	}
	v, err := c.jsonBody("readJournal", bodyKey)
	if err != nil {
		return Journal{}, err
	}
	return journalOf(v)
}

// jsonBody is the value of the container's one segment, body, whose plaintext is canonical JSON alone:
// malformed a container of other segments, before any frame is read, then every frame read in turn,
// each checked as a read checks it, and the plaintext parsed as canonical JSON.
func (c *OpenedContainer) jsonBody(op string, key []byte) (sealdcrypto.JSON, error) {
	if len(c.c.Segments) != 1 || c.c.Segments[0].Name != body {
		checkContentKey(op, key)
		return nil, notOneBody
	}
	r, err := c.read(op, body, key)
	if err != nil {
		return nil, err
	}
	if r.s.Plaintext > math.MaxInt {
		return nil, longBody
	}
	plaintext := make([]byte, 0, r.s.Plaintext)
	defer func() { clear(plaintext) }()
	for i := range r.s.Frames {
		p, err := r.frame(i)
		if err != nil {
			return nil, err
		}
		plaintext = append(plaintext, p...)
		clear(p)
	}
	return canonical.ParseJSON(plaintext)
}

// indexOf is v, a folder index's body, checked in steps 2 to 5 of the index's one order.
func indexOf(v sealdcrypto.JSON) (FolderIndex, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return FolderIndex{}, noIndex
	}
	format, ok := m["format"]
	if !ok {
		return FolderIndex{}, noIndex
	}
	// Another integer is a format this library does not know, and anything else none.
	n, ok := format.(int64)
	if !ok {
		return FolderIndex{}, noIndex
	}
	if n < 1 || n > IndexFormat {
		return FolderIndex{}, otherIndex
	}
	members := 2
	name, named := m["name"]
	if named {
		// Only format 3 has a name, and an index that has one holds it as non-empty text.
		if n < 3 || !nonEmptyText(name) {
			return FolderIndex{}, notAnIndex
		}
		members++
	}
	entries, ok := m["entries"].([]any)
	if !ok || len(m) != members {
		return FolderIndex{}, notAnIndex
	}
	if len(entries) > MaxIndexEntries {
		return FolderIndex{}, manyEntries
	}
	places := make([]string, 0, len(entries))
	locators := make([]string, 0, len(entries))
	for _, e := range entries {
		place, locator, err := indexEntryOf(e, n >= 2)
		if err != nil {
			return FolderIndex{}, err
		}
		places = append(places, place)
		if locator != nil {
			locators = append(locators, *locator)
		}
	}
	if repeats(places) {
		return FolderIndex{}, sharedPlace
	}
	if repeats(locators) {
		return FolderIndex{}, sharedLocate
	}
	index := FolderIndex{Format: int(n), Entries: entries}
	if named {
		index.Name = name.(string)
	}
	return index, nil
}

// repeats is whether two of list are one text. It sorts list, so it takes time n log n in its length.
func repeats(list []string) bool {
	slices.Sort(list)
	for i := 1; i < len(list); i++ {
		if list[i-1] == list[i] {
			return true
		}
	}
	return false
}

// journalOf is v, a pre-image journal's body, checked in step 4 of the journal's one order.
func journalOf(v sealdcrypto.JSON) (Journal, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return Journal{}, notAJournal
	}
	list, ok := m["saves"].([]any)
	if !ok || len(m) != 1 {
		return Journal{}, notAJournal
	}
	if len(list) > MaxJournalSaves {
		return Journal{}, manySaves
	}
	if len(list) == 0 {
		return Journal{}, notAJournal
	}
	saves := make([]JournalSave, 0, len(list))
	for _, item := range list {
		save, ok := item.(map[string]any)
		if !ok || len(save) != 2 {
			return Journal{}, notAJournal
		}
		envelope, ok := save["envelope"].(map[string]any)
		if !ok {
			return Journal{}, notAJournal
		}
		entry, ok := save["entry"]
		if !ok {
			return Journal{}, notAJournal
		}
		// A writer keeps each entry's hidden, so every journal's entry may hold one.
		if _, _, err := indexEntryOf(entry, true); err != nil {
			return Journal{}, err
		}
		saves = append(saves, JournalSave{Envelope: envelope, Entry: entry})
	}
	return Journal{Saves: saves}, nil
}

// The kinds of an index entry.
const (
	kindFile   = "file"
	kindRecord = "record"
	kindFolder = "folder"
	kindDomain = "domain"
)

// The values of hidden, each on the one kind it is for.
const (
	hiddenImportRecords = "import-records"
	hiddenImportRecord  = "import-record"
)

// indexEntryOf checks v, an index entry, against the Crypto API's table: an object of exactly the
// members its kind has, each in its form, hidden among them only where withHidden. It returns where the
// entry is, its path and name as one text no other path and name makes, and its locator, nil for a
// folder, which has none.
func indexEntryOf(v any, withHidden bool) (place string, locator *string, err error) {
	m, ok := v.(map[string]any)
	if !ok {
		return "", nil, notAnEntry
	}
	kind, _ := m["kind"].(string)
	var required, optional []string
	var hidden string
	switch kind {
	case kindFile, kindRecord:
		required = []string{"kind", "path", "name", "locator", "version"}
		optional = []string{"type", "created_at", "modified_at", "size", "index_fields", "pending", "retired"}
		if kind == kindFile {
			hidden = hiddenImportRecord
		}
	case kindDomain:
		required = []string{"kind", "path", "name", "locator"}
		hidden = hiddenImportRecords
	case kindFolder:
		required = []string{"kind", "path", "name"}
	default:
		return "", nil, notAnEntry
	}
	for _, name := range required {
		if _, ok := m[name]; !ok {
			return "", nil, notAnEntry
		}
	}
	if withHidden && hidden != "" {
		optional = append(optional, "hidden")
	}
	for name := range m {
		if !slices.Contains(required, name) && !slices.Contains(optional, name) {
			return "", nil, notAnEntry
		}
	}

	path, ok := m["path"].([]any)
	if !ok {
		return "", nil, notAnEntry
	}
	parts := make([][]byte, 0, len(path)+1)
	for _, p := range path {
		if !nonEmptyText(p) {
			return "", nil, notAnEntry
		}
		parts = append(parts, []byte(p.(string)))
	}
	if !nonEmptyText(m["name"]) {
		return "", nil, notAnEntry
	}
	// A path and name as one text: the path's tuple, then the name, so no two places share one.
	place = string(encoding.Tuple(encoding.Tuple(parts...), []byte(m["name"].(string))))
	if l, ok := m["locator"]; ok {
		// A locator is non-empty text wherever it is read (the Crypto API, Encoding).
		if !nonEmptyText(l) {
			return "", nil, notAnEntry
		}
		s := l.(string)
		locator = &s
	}
	if v, ok := m["version"]; ok && !integerFrom(v, 1) {
		return "", nil, notAnEntry
	}
	for _, name := range []string{"type", "created_at", "modified_at"} {
		if v, ok := m[name]; ok {
			if _, ok := v.(string); !ok {
				return "", nil, notAnEntry
			}
		}
	}
	if v, ok := m["size"]; ok && !integerFrom(v, 0) {
		return "", nil, notAnEntry
	}
	// index_fields is present where the dataset names a field, so it holds at least one, and {} is
	// refused.
	if v, ok := m["index_fields"]; ok {
		if fields, ok := v.(map[string]any); !ok || len(fields) == 0 {
			return "", nil, notAnEntry
		}
	}
	if v, ok := m["pending"]; ok && !ascendingVersions(v) {
		return "", nil, notAnEntry
	}
	if v, ok := m["retired"]; ok && v != true {
		return "", nil, notAnEntry
	}
	if v, ok := m["hidden"]; ok && v != hidden {
		return "", nil, notAnEntry
	}
	return place, locator, nil
}

// nonEmptyText is whether v is text of at least one character.
func nonEmptyText(v any) bool {
	s, ok := v.(string)
	return ok && s != ""
}

// integerFrom is whether v is an integer of least or more, as canonical JSON reads one.
func integerFrom(v any, least int64) bool {
	n, ok := v.(int64)
	return ok && n >= least
}

// ascendingVersions is whether v is an array of at least one integer from 1, ascending, none twice.
func ascendingVersions(v any) bool {
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return false
	}
	last := int64(0)
	for _, x := range list {
		n, ok := x.(int64)
		if !ok || n <= last {
			return false
		}
		last = n
	}
	return true
}

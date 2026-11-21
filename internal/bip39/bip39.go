// Package bip39 is BIP-39's English words, which the fingerprint words and the recovery phrase are
// written in. The list is bitcoin/bips', unchanged, and its test holds it to its SHA-256, so one altered
// or reordered word fails before two people read different words for one key.
//
// A recovery phrase is a secret, so neither Phrase nor ParsePhrase branches on its bits or indexes
// memory by them: each reads every word of the list, and every place of the text, and keeps what it
// needs under a mask.
package bip39

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"errors"
	"strings"
)

//go:embed english.txt
var english string

// longest is the longest word's length: every word is 3 to 8 letters.
const longest = 8

var (
	list = strings.Split(strings.TrimSuffix(english, "\n"), "\n")
	// padded is each word, then zeros to longest, so a word is read in the same time wherever it is.
	padded = func() [][longest]byte {
		p := make([][longest]byte, len(list))
		for i, w := range list {
			copy(p[i][:], w)
		}
		return p
	}()
)

// ParsePhrase's errors, which the caller refuses as its operation sets.
var (
	ErrForm     = errors.New("bip39: text that is not the words in lower case, separated by one space")
	ErrWord     = errors.New("bip39: a word outside the list")
	ErrChecksum = errors.New("bip39: a checksum that fails")
)

// Words is entropy as BIP-39 English words: its bits, then the first len(entropy)/4 bits of its
// SHA-256, 11 bits a word, so 16, 20, 24, 28 or 32 bytes are 12, 15, 18, 21 or 24 words. The words are
// strings, which cannot be zeroised, so it is for public bytes alone; a secret's words are Phrase's.
//
// Any other length is a fault, and panics.
func Words(entropy []byte) []string {
	bits := checksummed("Words", entropy)
	defer clear(bits)
	words := make([]string, wordCount(len(entropy)))
	for w := range words {
		word, length := lookUp(index(bits, w))
		words[w] = string(word[:length])
	}
	return words
}

// Phrase is entropy's words, as Words gives them, each in lower case as the list writes it, separated
// by one space, in a new slice for the caller to zeroise. Any other length is a fault, and panics.
func Phrase(entropy []byte) []byte {
	bits := checksummed("Phrase", entropy)
	defer clear(bits)
	count := wordCount(len(entropy))
	out := make([]byte, count*(longest+1))
	defer clear(out)
	start := 0
	for w := range count {
		word, length := lookUp(index(bits, w))
		// Each place of out is written under a mask, so where a word lands reads nothing of its length.
		for j := range out {
			for k := range longest {
				out[j] |= word[k] & mask(eq(j, start+k)&less(k, length))
			}
			if w < count-1 {
				out[j] |= ' ' & mask(eq(j, start+length))
			}
		}
		clear(word[:])
		start += length + 1
	}
	phrase := make([]byte, start-1)
	copy(phrase, out)
	return phrase
}

// ParsePhrase is Phrase's inverse: phrase, exactly count words in lower case, each as the list writes
// it, separated by one space, with none before the first or after the last, is the entropy whose phrase
// it is. It returns ErrForm for any other text, ErrWord where a word is not in the list, and
// ErrChecksum where the last bits are not the checksum of the rest. The entropy is the caller's to
// zeroise.
//
// A count BIP-39 does not have, other than 12 to 24 in steps of 3, is a fault, and panics.
func ParsePhrase(phrase []byte, count int) ([]byte, error) {
	if count < 12 || count > 24 || count%3 != 0 {
		panic("bip39: ParsePhrase: not 12 to 24 words in steps of 3")
	}
	// A phrase's length is public, as the text it was given in is.
	if len(phrase) > count*(longest+1)-1 {
		return nil, ErrForm
	}
	words := make([][longest]byte, count)
	lengths := make([]int, count)
	defer func() {
		for i := range words {
			clear(words[i][:])
		}
		clear(lengths)
	}()
	w, p, bad := 0, 0, 0
	for _, c := range phrase {
		space := subtle.ConstantTimeByteEq(c, ' ')
		letter := lower(c)
		bad |= 1 ^ (space | letter)
		bad |= space & eq(p, 0)        // a space first, or after another
		bad |= letter & eq(p, longest) // a word longer than any
		for i := range words {
			at := letter & eq(i, w)
			for k := range longest {
				words[i][k] |= c & mask(at&eq(k, p))
			}
			lengths[i] += at
		}
		w += space
		p = (p + 1) & -letter
	}
	bad |= eq(p, 0)           // a space last, or no text
	bad |= 1 ^ eq(w, count-1) // another number of words
	if bad != 0 {
		return nil, ErrForm
	}
	n := count * 4 / 3
	bits := make([]byte, n+1)
	defer clear(bits)
	found := 1
	for w := range words {
		index, in := 0, 0
		for i := range padded {
			e := subtle.ConstantTimeCompare(words[w][:], padded[i][:]) & eq(lengths[w], len(list[i]))
			in |= e
			index |= i & -e
		}
		found &= in
		for b := range 11 {
			at := w*11 + b
			bits[at/8] |= byte(index>>(10-b)&1) << (7 - at%8)
		}
	}
	if found != 1 {
		return nil, ErrWord
	}
	entropy := make([]byte, n)
	copy(entropy, bits)
	sum := sha256.Sum256(entropy)
	checksum := byte(0xff) << (8 - n/4)
	if subtle.ConstantTimeByteEq(sum[0]&checksum, bits[n]&checksum) != 1 {
		clear(entropy)
		return nil, ErrChecksum
	}
	return entropy, nil
}

// checksummed is entropy, then the first byte of its SHA-256, whose first len(entropy)/4 bits are the
// checksum, in a new slice for the caller to clear.
func checksummed(op string, entropy []byte) []byte {
	n := len(entropy)
	if n < 16 || n > 32 || n%4 != 0 {
		panic("bip39: " + op + ": entropy is not 16 to 32 bytes in steps of 4")
	}
	sum := sha256.Sum256(entropy)
	return append(append(make([]byte, 0, n+1), entropy...), sum[0])
}

func wordCount(n int) int { return (n*8 + n/4) / 11 }

// index is the w-th group of 11 bits, big-endian.
func index(bits []byte, w int) int {
	i := 0
	for b := w * 11; b < w*11+11; b++ {
		i = i<<1 | int(bits[b/8]>>(7-b%8)&1)
	}
	return i
}

// lookUp is the word at index, padded with zeros, and its length, read from every word of the list.
func lookUp(index int) ([longest]byte, int) {
	var word [longest]byte
	length := 0
	for i := range padded {
		m := -eq(i, index)
		for k := range word {
			word[k] |= padded[i][k] & byte(m) //nolint:gosec // m is 0 or -1, all ones
		}
		length |= len(list[i]) & m
	}
	return word, length
}

// eq is 1 where a == b and 0 otherwise. Every int here is below 2^31.
func eq(a, b int) int {
	return subtle.ConstantTimeEq(int32(a), int32(b)) //nolint:gosec // both are below 2^31
}

// less is 1 where a < b and 0 otherwise, for a and b from 0 to 2^31 - 1.
func less(a, b int) int {
	return int(uint32(int32(a)-int32(b)) >> 31) //nolint:gosec // both are below 2^31
}

// lower is 1 where c is a letter from a to z and 0 otherwise.
func lower(c byte) int {
	d := int32(c) - 'a'
	return int(1 ^ (uint32(d)>>31 | uint32(25-d)>>31)) //nolint:gosec // the sign bit is the bit read
}

// mask is 0xff where bit is 1 and 0 where it is 0.
func mask(bit int) byte {
	return byte(-bit) //nolint:gosec // bit is 0 or 1
}

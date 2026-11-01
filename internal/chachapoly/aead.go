// Package chachapoly implements ChaCha20, Poly1305 and the
// ChaCha20-Poly1305 AEAD of RFC 8439, plus HChaCha20 and
// XChaCha20-Poly1305 of draft-irtf-cfrg-xchacha-03.
package chachapoly

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

const (
	// KeySize is the key size of both AEADs.
	KeySize = 32
	// NonceSize is the ChaCha20-Poly1305 nonce size.
	NonceSize = 12
	// NonceSizeX is the XChaCha20-Poly1305 nonce size.
	NonceSizeX = 24
	// Overhead is the size of the Poly1305 tag appended to the ciphertext.
	Overhead = tagSize

	// maxPlaintext keeps the 32-bit block counter, which starts at 1 for
	// the payload, from wrapping: 2^32 - 1 blocks of 64 bytes.
	maxPlaintext = (1<<32 - 1) * 64
)

var (
	ErrKeySize   = errors.New("chachapoly: key must be 32 bytes")
	ErrNonceSize = errors.New("chachapoly: wrong nonce size")
	ErrTooLarge  = errors.New("chachapoly: message too large")
	ErrOpen      = errors.New("chachapoly: message authentication failed")
)

// Seal encrypts and authenticates plaintext and authenticates ad with
// ChaCha20-Poly1305 (RFC 8439 §2.8), appends ciphertext||tag to dst and
// returns the result. key must be 32 bytes and nonce 12 bytes. plaintext
// and dst may overlap only if dst is plaintext[:0].
func Seal(dst, key, nonce, plaintext, ad []byte) ([]byte, error) {
	k, n, err := params(key, nonce, NonceSize)
	if err != nil {
		return nil, err
	}
	if uint64(len(plaintext)) > maxPlaintext {
		return nil, ErrTooLarge
	}
	return seal(dst, &k, &n, plaintext, ad), nil
}

// Open authenticates ciphertext||tag and ad with ChaCha20-Poly1305 and, if
// the tag is valid, appends the plaintext to dst and returns the result.
// Nothing is written to dst when authentication fails. ciphertext and dst
// may overlap only if dst is ciphertext[:0].
func Open(dst, key, nonce, ciphertext, ad []byte) ([]byte, error) {
	k, n, err := params(key, nonce, NonceSize)
	if err != nil {
		return nil, err
	}
	return open(dst, &k, &n, ciphertext, ad)
}

// XSeal is Seal for XChaCha20-Poly1305: nonce must be 24 bytes.
func XSeal(dst, key, nonce, plaintext, ad []byte) ([]byte, error) {
	k, n, err := xParams(key, nonce)
	if err != nil {
		return nil, err
	}
	if uint64(len(plaintext)) > maxPlaintext {
		return nil, ErrTooLarge
	}
	return seal(dst, &k, &n, plaintext, ad), nil
}

// XOpen is Open for XChaCha20-Poly1305: nonce must be 24 bytes.
func XOpen(dst, key, nonce, ciphertext, ad []byte) ([]byte, error) {
	k, n, err := xParams(key, nonce)
	if err != nil {
		return nil, err
	}
	return open(dst, &k, &n, ciphertext, ad)
}

func params(key, nonce []byte, nonceSize int) (k [KeySize]byte, n [NonceSize]byte, err error) {
	if len(key) != KeySize {
		return k, n, ErrKeySize
	}
	if len(nonce) != nonceSize {
		return k, n, ErrNonceSize
	}
	copy(k[:], key)
	copy(n[:], nonce)
	return k, n, nil
}

// xParams derives the ChaCha20-Poly1305 key and nonce of an XChaCha20-Poly1305
// operation: the subkey is HChaCha20(key, nonce[:16]) and the nonce is four
// zero bytes followed by nonce[16:24].
func xParams(key, nonce []byte) (k [KeySize]byte, n [NonceSize]byte, err error) {
	if len(key) != KeySize {
		return k, n, ErrKeySize
	}
	if len(nonce) != NonceSizeX {
		return k, n, ErrNonceSize
	}
	var key32 [KeySize]byte
	var h [16]byte
	copy(key32[:], key)
	copy(h[:], nonce[:16])
	k = HChaCha20(&key32, &h)
	copy(n[4:], nonce[16:])
	return k, n, nil
}

func seal(dst []byte, key *[KeySize]byte, nonce *[NonceSize]byte, plaintext, ad []byte) []byte {
	ret, out := sliceForAppend(dst, len(plaintext)+tagSize)
	ct := out[:len(plaintext)]
	xorKeyStream(ct, plaintext, key, 1, nonce)
	tag := aeadTag(key, nonce, ct, ad)
	copy(out[len(plaintext):], tag[:])
	return ret
}

func open(dst []byte, key *[KeySize]byte, nonce *[NonceSize]byte, ciphertext, ad []byte) ([]byte, error) {
	if len(ciphertext) < tagSize {
		return nil, ErrOpen
	}
	ct := ciphertext[:len(ciphertext)-tagSize]
	if uint64(len(ct)) > maxPlaintext {
		return nil, ErrOpen
	}
	tag := aeadTag(key, nonce, ct, ad)
	if subtle.ConstantTimeCompare(tag[:], ciphertext[len(ct):]) != 1 {
		return nil, ErrOpen
	}
	ret, out := sliceForAppend(dst, len(ct))
	xorKeyStream(out, ct, key, 1, nonce)
	return ret, nil
}

// aeadTag computes the tag of RFC 8439 §2.8 over ad and ct with the
// one-time key of §2.6 (the first 32 bytes of block 0).
func aeadTag(key *[KeySize]byte, nonce *[NonceSize]byte, ct, ad []byte) [tagSize]byte {
	block0 := chachaBlock(key, 0, nonce)
	var otk [32]byte
	copy(otk[:], block0[:32])

	p := newPoly1305(&otk)
	p.write(ad)
	p.pad16()
	p.write(ct)
	p.pad16()
	var lens [16]byte
	binary.LittleEndian.PutUint64(lens[0:], uint64(len(ad)))
	binary.LittleEndian.PutUint64(lens[8:], uint64(len(ct)))
	p.write(lens[:])
	return p.finish()
}

// sliceForAppend extends in by n bytes, reusing its capacity when possible,
// and returns the whole slice and the n new bytes.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	total := len(in) + n
	if cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	return head, head[len(in):]
}

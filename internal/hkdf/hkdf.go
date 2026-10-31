// Package hkdf implements HMAC (RFC 2104) and HKDF (RFC 5869) over any
// hash.Hash constructor, and the KDF1, KDF2 and KDF3 functions of the
// WireGuard protocol over HMAC-BLAKE2s.
package hkdf

import (
	"errors"
	"hash"

	"github.com/CesarManzoCode/malla-wg/internal/blake2s"
)

// ErrLength reports an Expand output longer than 255 hash blocks.
var ErrLength = errors.New("hkdf: output longer than 255 hash lengths")

type hmac struct {
	inner, outer hash.Hash
	ipad, opad   []byte
}

// NewHMAC returns HMAC (RFC 2104) keyed with key over the hash that newHash
// builds. A key longer than the block size is hashed first; the key is then
// padded with zeros to the block size.
func NewHMAC(newHash func() hash.Hash, key []byte) hash.Hash {
	m := &hmac{inner: newHash(), outer: newHash()}
	bs := m.inner.BlockSize()
	if len(key) > bs {
		m.outer.Write(key)
		key = m.outer.Sum(nil)
		m.outer.Reset()
	}
	m.ipad = make([]byte, bs)
	m.opad = make([]byte, bs)
	copy(m.ipad, key)
	copy(m.opad, key)
	for i := range m.ipad {
		m.ipad[i] ^= 0x36
		m.opad[i] ^= 0x5c
	}
	m.inner.Write(m.ipad)
	return m
}

func (m *hmac) Write(p []byte) (int, error) { return m.inner.Write(p) }
func (m *hmac) Size() int                   { return m.outer.Size() }
func (m *hmac) BlockSize() int              { return m.inner.BlockSize() }

func (m *hmac) Reset() {
	m.inner.Reset()
	m.inner.Write(m.ipad)
}

// Sum appends H(K ^ opad || H(K ^ ipad || text)) to b without changing the
// state.
func (m *hmac) Sum(b []byte) []byte {
	in := m.inner.Sum(nil)
	m.outer.Reset()
	m.outer.Write(m.opad)
	m.outer.Write(in)
	return m.outer.Sum(b)
}

// Extract is HKDF-Extract (RFC 5869 §2.2): HMAC(salt, ikm). An empty salt
// is replaced by HashLen zeros.
func Extract(newHash func() hash.Hash, salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, newHash().Size())
	}
	m := NewHMAC(newHash, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

// Expand is HKDF-Expand (RFC 5869 §2.3): the first length bytes of
// T(1) || T(2) || … with T(i) = HMAC(prk, T(i-1) || info || i).
func Expand(newHash func() hash.Hash, prk, info []byte, length int) ([]byte, error) {
	m := NewHMAC(newHash, prk)
	if length < 0 || length > 255*m.Size() {
		return nil, ErrLength
	}
	okm := make([]byte, 0, length)
	var t []byte
	for i := byte(1); len(okm) < length; i++ {
		m.Reset()
		m.Write(t)
		m.Write(info)
		m.Write([]byte{i})
		t = m.Sum(t[:0])
		okm = append(okm, t[:min(len(t), length-len(okm))]...)
	}
	return okm, nil
}

// HashSize is the BLAKE2s-256 output size used by the WireGuard KDFs.
const HashSize = blake2s.Size

// HMACBlake2s returns HMAC-BLAKE2s-256(key, data[0] || data[1] || …), the
// Hmac of the WireGuard protocol page.
func HMACBlake2s(key []byte, data ...[]byte) [HashSize]byte {
	m := NewHMAC(blake2s.New256, key)
	for _, d := range data {
		m.Write(d)
	}
	var out [HashSize]byte
	m.Sum(out[:0])
	return out
}

// kdf computes τ1..τn of the WireGuard protocol page:
// τ0 = Hmac(key, input), τ1 = Hmac(τ0, 0x1), τi = Hmac(τ0, τ(i-1) || i).
// It is HKDF with salt key, ikm input, empty info and n·32 output bytes.
func kdf(out [][HashSize]byte, key, input []byte) {
	t0 := HMACBlake2s(key, input)
	var prev []byte
	for i := range out {
		out[i] = HMACBlake2s(t0[:], prev, []byte{byte(i + 1)})
		prev = out[i][:]
	}
	clear(t0[:])
}

// KDF1 returns τ1 of Kdf1(key, input).
func KDF1(key, input []byte) [HashSize]byte {
	var out [1][HashSize]byte
	kdf(out[:], key, input)
	return out[0]
}

// KDF2 returns τ1, τ2 of Kdf2(key, input).
func KDF2(key, input []byte) (t1, t2 [HashSize]byte) {
	var out [2][HashSize]byte
	kdf(out[:], key, input)
	return out[0], out[1]
}

// KDF3 returns τ1, τ2, τ3 of Kdf3(key, input).
func KDF3(key, input []byte) (t1, t2, t3 [HashSize]byte) {
	var out [3][HashSize]byte
	kdf(out[:], key, input)
	return out[0], out[1], out[2]
}

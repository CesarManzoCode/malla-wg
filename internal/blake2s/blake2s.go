// Package blake2s implements BLAKE2s (RFC 7693) with a key of 0 to 32 bytes
// and a digest of 1 to 32 bytes, plus the Keyed-Blake2s MAC that WireGuard
// uses for mac1 and mac2.
package blake2s

import (
	"encoding/binary"
	"errors"
	"hash"
	"math/bits"
)

const (
	// BlockSize is the BLAKE2s block size in bytes.
	BlockSize = 64
	// Size is the largest (and default) digest size.
	Size = 32
	// MaxKeySize is the largest key size.
	MaxKeySize = 32
	// MACSize is the output size of MAC.
	MACSize = 16
)

var (
	ErrSize    = errors.New("blake2s: digest size must be 1 to 32 bytes")
	ErrKeySize = errors.New("blake2s: key must be at most 32 bytes")
)

// iv is the BLAKE2s initialization vector (RFC 7693 §2.6).
var iv = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

// sigma is the message schedule (RFC 7693 §2.7).
var sigma = [10][16]byte{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

// digest is the streaming state. The last block is kept in buf until Sum,
// because only the final compression sets the last-block flag.
type digest struct {
	h      [8]uint32
	t      uint64 // bytes compressed so far
	buf    [BlockSize]byte
	n      int // bytes buffered in buf
	size   int
	keyLen int
	key    [MaxKeySize]byte
}

// New returns a BLAKE2s hash with a digest of size bytes, keyed with key
// (0 to 32 bytes; empty means unkeyed). It implements hash.Hash.
func New(size int, key []byte) (hash.Hash, error) {
	d, err := newDigest(size, key)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// New256 returns an unkeyed BLAKE2s-256 hash. It fits as the constructor
// argument of HMAC and HKDF.
func New256() hash.Hash {
	d, _ := newDigest(Size, nil)
	return d
}

func newDigest(size int, key []byte) (*digest, error) {
	if size < 1 || size > Size {
		return nil, ErrSize
	}
	if len(key) > MaxKeySize {
		return nil, ErrKeySize
	}
	d := &digest{size: size, keyLen: len(key)}
	copy(d.key[:], key)
	d.Reset()
	return d, nil
}

// Sum256 returns the unkeyed BLAKE2s-256 digest of data.
func Sum256(data []byte) [Size]byte {
	var d digest
	d.size = Size
	d.Reset()
	d.Write(data)
	var out [Size]byte
	d.final(out[:])
	return out
}

// MAC returns Keyed-Blake2s(key, data, 16) as the WireGuard protocol defines
// it: a 32-byte key for mac1 and the 16-byte cookie for mac2. It panics if
// key is longer than 32 bytes.
func MAC(key, data []byte) [MACSize]byte {
	if len(key) > MaxKeySize {
		panic(ErrKeySize)
	}
	d := digest{size: MACSize, keyLen: len(key)}
	copy(d.key[:], key)
	d.Reset()
	d.Write(data)
	var out [MACSize]byte
	d.final(out[:])
	return out
}

func (d *digest) Size() int      { return d.size }
func (d *digest) BlockSize() int { return BlockSize }

// Reset restores the initial state; a keyed hash starts with the key padded
// to a full block (RFC 7693 §3.3).
func (d *digest) Reset() {
	d.h = iv
	d.h[0] ^= 0x01010000 ^ uint32(d.keyLen)<<8 ^ uint32(d.size)
	d.t = 0
	d.buf = [BlockSize]byte{}
	d.n = 0
	if d.keyLen > 0 {
		copy(d.buf[:], d.key[:d.keyLen])
		d.n = BlockSize
	}
}

func (d *digest) Write(p []byte) (int, error) {
	written := len(p)
	for len(p) > 0 {
		if d.n == BlockSize {
			d.t += BlockSize
			compress(&d.h, d.t, &d.buf, false)
			d.n = 0
		}
		c := copy(d.buf[d.n:], p)
		d.n += c
		p = p[c:]
	}
	return written, nil
}

// Sum appends the digest to b without changing the state.
func (d *digest) Sum(b []byte) []byte {
	c := *d
	var out [Size]byte
	c.final(out[:d.size])
	return append(b, out[:d.size]...)
}

// final pads the buffered block with zeros, compresses it with the
// last-block flag and writes the first len(out) bytes of h little-endian.
func (d *digest) final(out []byte) {
	d.t += uint64(d.n)
	clear(d.buf[d.n:])
	compress(&d.h, d.t, &d.buf, true)
	var full [Size]byte
	for i, w := range d.h {
		binary.LittleEndian.PutUint32(full[4*i:], w)
	}
	copy(out, full[:])
}

func g(v *[16]uint32, a, b, c, d int, x, y uint32) {
	v[a] += v[b] + x
	v[d] = bits.RotateLeft32(v[d]^v[a], -16)
	v[c] += v[d]
	v[b] = bits.RotateLeft32(v[b]^v[c], -12)
	v[a] += v[b] + y
	v[d] = bits.RotateLeft32(v[d]^v[a], -8)
	v[c] += v[d]
	v[b] = bits.RotateLeft32(v[b]^v[c], -7)
}

// compress is the function F of RFC 7693 §3.2 with t the byte offset at the
// end of block.
func compress(h *[8]uint32, t uint64, block *[BlockSize]byte, last bool) {
	var m [16]uint32
	for i := range m {
		m[i] = binary.LittleEndian.Uint32(block[4*i:])
	}
	var v [16]uint32
	copy(v[:8], h[:])
	copy(v[8:], iv[:])
	v[12] ^= uint32(t)
	v[13] ^= uint32(t >> 32)
	if last {
		v[14] = ^v[14]
	}
	for i := range sigma {
		s := &sigma[i]
		g(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
		g(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
		g(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
		g(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
		g(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
		g(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
		g(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
		g(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
	}
	for i := range h {
		h[i] ^= v[i] ^ v[i+8]
	}
}

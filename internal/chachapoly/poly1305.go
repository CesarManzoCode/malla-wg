package chachapoly

import "encoding/binary"

const tagSize = 16

// poly1305 is the one-time authenticator of RFC 8439 §2.5. The accumulator
// h and the clamped r are held in five 26-bit limbs so that every product
// fits in 64 bits; the final reduction modulo 2^130 - 5 selects with a mask
// instead of branching.
type poly1305 struct {
	r   [5]uint32
	s   [4]uint32
	h   [5]uint32
	buf [16]byte
	n   int
}

const mask26 = 1<<26 - 1

func newPoly1305(key *[32]byte) *poly1305 {
	p := new(poly1305)
	// r is clamped as in RFC 8439 §2.5 while it is split into limbs.
	p.r[0] = binary.LittleEndian.Uint32(key[0:]) & 0x3ffffff
	p.r[1] = (binary.LittleEndian.Uint32(key[3:]) >> 2) & 0x3ffff03
	p.r[2] = (binary.LittleEndian.Uint32(key[6:]) >> 4) & 0x3ffc0ff
	p.r[3] = (binary.LittleEndian.Uint32(key[9:]) >> 6) & 0x3f03fff
	p.r[4] = (binary.LittleEndian.Uint32(key[12:]) >> 8) & 0x00fffff
	for i := 0; i < 4; i++ {
		p.s[i] = binary.LittleEndian.Uint32(key[16+4*i:])
	}
	return p
}

// block adds one 16-byte block, with hibit set to 1<<24 to append the 2^128
// bit of a full block, and multiplies the accumulator by r.
func (p *poly1305) block(m []byte, hibit uint32) {
	r0, r1, r2, r3, r4 := uint64(p.r[0]), uint64(p.r[1]), uint64(p.r[2]), uint64(p.r[3]), uint64(p.r[4])
	s1, s2, s3, s4 := r1*5, r2*5, r3*5, r4*5

	h0 := uint64(p.h[0] + binary.LittleEndian.Uint32(m[0:])&mask26)
	h1 := uint64(p.h[1] + (binary.LittleEndian.Uint32(m[3:])>>2)&mask26)
	h2 := uint64(p.h[2] + (binary.LittleEndian.Uint32(m[6:])>>4)&mask26)
	h3 := uint64(p.h[3] + (binary.LittleEndian.Uint32(m[9:])>>6)&mask26)
	h4 := uint64(p.h[4] + (binary.LittleEndian.Uint32(m[12:])>>8 | hibit))

	d0 := h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1
	d1 := h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2
	d2 := h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3
	d3 := h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4
	d4 := h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0

	c := d0 >> 26
	h0 = d0 & mask26
	d1 += c
	c = d1 >> 26
	h1 = d1 & mask26
	d2 += c
	c = d2 >> 26
	h2 = d2 & mask26
	d3 += c
	c = d3 >> 26
	h3 = d3 & mask26
	d4 += c
	c = d4 >> 26
	h4 = d4 & mask26
	h0 += c * 5
	c = h0 >> 26
	h0 &= mask26
	h1 += c

	p.h = [5]uint32{uint32(h0), uint32(h1), uint32(h2), uint32(h3), uint32(h4)}
}

// write absorbs m as consecutive 16-byte blocks, buffering a trailing
// partial block until more data or finish arrives.
func (p *poly1305) write(m []byte) {
	if p.n > 0 {
		k := copy(p.buf[p.n:], m)
		p.n += k
		m = m[k:]
		if p.n < len(p.buf) {
			return
		}
		p.block(p.buf[:], 1<<24)
		p.n = 0
	}
	for len(m) >= 16 {
		p.block(m[:16], 1<<24)
		m = m[16:]
	}
	p.n = copy(p.buf[:], m)
}

// pad16 completes a buffered partial block with zeros, as the AEAD
// construction of RFC 8439 §2.8 does after the AAD and the ciphertext.
func (p *poly1305) pad16() {
	if p.n == 0 {
		return
	}
	clear(p.buf[p.n:])
	p.block(p.buf[:], 1<<24)
	p.n = 0
}

// finish processes a last partial block (padded with a 1 bit and zeros),
// reduces h modulo 2^130 - 5 and returns (h + s) mod 2^128.
func (p *poly1305) finish() [tagSize]byte {
	if p.n > 0 {
		p.buf[p.n] = 1
		clear(p.buf[p.n+1:])
		p.block(p.buf[:], 0)
		p.n = 0
	}

	h0, h1, h2, h3, h4 := p.h[0], p.h[1], p.h[2], p.h[3], p.h[4]
	c := h1 >> 26
	h1 &= mask26
	h2 += c
	c = h2 >> 26
	h2 &= mask26
	h3 += c
	c = h3 >> 26
	h3 &= mask26
	h4 += c
	c = h4 >> 26
	h4 &= mask26
	h0 += c * 5
	c = h0 >> 26
	h0 &= mask26
	h1 += c

	// g = h + 5 - 2^130; if it does not borrow, h >= p and g is the result.
	g0 := h0 + 5
	c = g0 >> 26
	g0 &= mask26
	g1 := h1 + c
	c = g1 >> 26
	g1 &= mask26
	g2 := h2 + c
	c = g2 >> 26
	g2 &= mask26
	g3 := h3 + c
	c = g3 >> 26
	g3 &= mask26
	g4 := h4 + c - 1<<26

	// mask is all ones when g4 did not wrap (h >= p), zero otherwise.
	mask := (g4 >> 31) - 1
	h0 = h0&^mask | g0&mask
	h1 = h1&^mask | g1&mask
	h2 = h2&^mask | g2&mask
	h3 = h3&^mask | g3&mask
	h4 = h4&^mask | g4&mask

	// Repack into four 32-bit words and add s modulo 2^128.
	w0 := h0 | h1<<26
	w1 := h1>>6 | h2<<20
	w2 := h2>>12 | h3<<14
	w3 := h3>>18 | h4<<8

	var tag [tagSize]byte
	f := uint64(w0) + uint64(p.s[0])
	binary.LittleEndian.PutUint32(tag[0:], uint32(f))
	f = uint64(w1) + uint64(p.s[1]) + f>>32
	binary.LittleEndian.PutUint32(tag[4:], uint32(f))
	f = uint64(w2) + uint64(p.s[2]) + f>>32
	binary.LittleEndian.PutUint32(tag[8:], uint32(f))
	f = uint64(w3) + uint64(p.s[3]) + f>>32
	binary.LittleEndian.PutUint32(tag[12:], uint32(f))
	return tag
}

// poly1305Sum is the one-shot MAC of msg under a 32-byte one-time key.
func poly1305Sum(key *[32]byte, msg []byte) [tagSize]byte {
	p := newPoly1305(key)
	p.write(msg)
	return p.finish()
}

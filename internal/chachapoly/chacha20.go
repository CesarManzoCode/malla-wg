package chachapoly

import (
	"encoding/binary"
	"math/bits"
)

// The "expand 32-byte k" constants of RFC 8439 §2.3.
const (
	sigma0 = 0x61707865
	sigma1 = 0x3320646e
	sigma2 = 0x79622d32
	sigma3 = 0x6b206574
)

func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 16)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 12)
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 8)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 7)
	return a, b, c, d
}

// rounds applies the 20 ChaCha rounds (10 column and 10 diagonal rounds)
// to s in place.
func rounds(s *[16]uint32) {
	for i := 0; i < 10; i++ {
		s[0], s[4], s[8], s[12] = quarterRound(s[0], s[4], s[8], s[12])
		s[1], s[5], s[9], s[13] = quarterRound(s[1], s[5], s[9], s[13])
		s[2], s[6], s[10], s[14] = quarterRound(s[2], s[6], s[10], s[14])
		s[3], s[7], s[11], s[15] = quarterRound(s[3], s[7], s[11], s[15])
		s[0], s[5], s[10], s[15] = quarterRound(s[0], s[5], s[10], s[15])
		s[1], s[6], s[11], s[12] = quarterRound(s[1], s[6], s[11], s[12])
		s[2], s[7], s[8], s[13] = quarterRound(s[2], s[7], s[8], s[13])
		s[3], s[4], s[9], s[14] = quarterRound(s[3], s[4], s[9], s[14])
	}
}

// initState lays out constants, key, counter and nonce as in RFC 8439 §2.3.
func initState(key *[KeySize]byte, counter uint32, nonce *[NonceSize]byte) [16]uint32 {
	var s [16]uint32
	s[0], s[1], s[2], s[3] = sigma0, sigma1, sigma2, sigma3
	for i := 0; i < 8; i++ {
		s[4+i] = binary.LittleEndian.Uint32(key[4*i:])
	}
	s[12] = counter
	s[13] = binary.LittleEndian.Uint32(nonce[0:])
	s[14] = binary.LittleEndian.Uint32(nonce[4:])
	s[15] = binary.LittleEndian.Uint32(nonce[8:])
	return s
}

// chachaBlock is the ChaCha20 block function of RFC 8439 §2.3.
func chachaBlock(key *[KeySize]byte, counter uint32, nonce *[NonceSize]byte) [64]byte {
	in := initState(key, counter, nonce)
	s := in
	rounds(&s)
	var out [64]byte
	for i := range s {
		binary.LittleEndian.PutUint32(out[4*i:], s[i]+in[i])
	}
	return out
}

// xorKeyStream is the ChaCha20 encryption of RFC 8439 §2.4: dst = src XOR
// the key stream starting at block counter. dst and src must have the same
// length and may be the same slice. The caller bounds len(src) so that the
// 32-bit counter does not wrap.
func xorKeyStream(dst, src []byte, key *[KeySize]byte, counter uint32, nonce *[NonceSize]byte) {
	for len(src) > 0 {
		ks := chachaBlock(key, counter, nonce)
		n := min(len(src), len(ks))
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ ks[i]
		}
		dst, src = dst[n:], src[n:]
		counter++
	}
}

// HChaCha20 derives a 32-byte subkey from key and the first 16 bytes of an
// XChaCha20 nonce (draft-irtf-cfrg-xchacha-03 §2.2): the ChaCha20 rounds
// over the state with the 16 bytes in place of counter and nonce, without
// the final addition, keeping words 0..3 and 12..15.
func HChaCha20(key *[KeySize]byte, nonce *[16]byte) [KeySize]byte {
	var s [16]uint32
	s[0], s[1], s[2], s[3] = sigma0, sigma1, sigma2, sigma3
	for i := 0; i < 8; i++ {
		s[4+i] = binary.LittleEndian.Uint32(key[4*i:])
	}
	for i := 0; i < 4; i++ {
		s[12+i] = binary.LittleEndian.Uint32(nonce[4*i:])
	}
	rounds(&s)
	var out [KeySize]byte
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(out[4*i:], s[i])
		binary.LittleEndian.PutUint32(out[16+4*i:], s[12+i])
	}
	return out
}

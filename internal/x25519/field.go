package x25519

import (
	"encoding/binary"
	"math/bits"
)

// fieldElement is an element of GF(2^255 - 19) in radix 2^51:
// l[0] + l[1]·2^51 + l[2]·2^102 + l[3]·2^153 + l[4]·2^204.
//
// Every function here returns limbs below 2^51 + 2^18, which is the bound
// feMul relies on to keep its 128-bit accumulators and carries from
// overflowing. No function branches on or indexes by limb values.
type fieldElement [5]uint64

const maskLow51 = 1<<51 - 1

// feFromBytes decodes a little-endian u-coordinate. Bit 255 is ignored, as
// RFC 7748 §5 requires; values in [p, 2^255) are accepted and reduce
// naturally in the arithmetic.
func feFromBytes(b *[32]byte) fieldElement {
	return fieldElement{
		binary.LittleEndian.Uint64(b[0:8]) & maskLow51,
		(binary.LittleEndian.Uint64(b[6:14]) >> 3) & maskLow51,
		(binary.LittleEndian.Uint64(b[12:20]) >> 6) & maskLow51,
		(binary.LittleEndian.Uint64(b[19:27]) >> 1) & maskLow51,
		(binary.LittleEndian.Uint64(b[24:32]) >> 12) & maskLow51,
	}
}

// feToBytes encodes the canonical (fully reduced) value of v.
func feToBytes(v fieldElement) [32]byte {
	v = feCarry(v)
	// Now v < 2^255 + 2^18·19 < 2p. c is 1 exactly when v + 19 >= 2^255,
	// that is, when v >= p.
	c := (v[0] + 19) >> 51
	c = (v[1] + c) >> 51
	c = (v[2] + c) >> 51
	c = (v[3] + c) >> 51
	c = (v[4] + c) >> 51

	// Subtract c·p by adding 19·c and dropping bit 255.
	v[0] += 19 * c
	v[1] += v[0] >> 51
	v[0] &= maskLow51
	v[2] += v[1] >> 51
	v[1] &= maskLow51
	v[3] += v[2] >> 51
	v[2] &= maskLow51
	v[4] += v[3] >> 51
	v[3] &= maskLow51
	v[4] &= maskLow51

	var out [32]byte
	binary.LittleEndian.PutUint64(out[0:8], v[0]|v[1]<<51)
	binary.LittleEndian.PutUint64(out[8:16], v[1]>>13|v[2]<<38)
	binary.LittleEndian.PutUint64(out[16:24], v[2]>>26|v[3]<<25)
	binary.LittleEndian.PutUint64(out[24:32], v[3]>>39|v[4]<<12)
	return out
}

// feCarry brings every limb of v below 2^51 + 2^18, folding the carry out
// of the top limb back into the bottom one (2^255 ≡ 19).
func feCarry(v fieldElement) fieldElement {
	c0 := v[0] >> 51
	c1 := v[1] >> 51
	c2 := v[2] >> 51
	c3 := v[3] >> 51
	c4 := v[4] >> 51
	return fieldElement{
		v[0]&maskLow51 + c4*19,
		v[1]&maskLow51 + c0,
		v[2]&maskLow51 + c1,
		v[3]&maskLow51 + c2,
		v[4]&maskLow51 + c3,
	}
}

func feAdd(a, b fieldElement) fieldElement {
	return feCarry(fieldElement{a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3], a[4] + b[4]})
}

// feSub computes a - b as a + 2p - b so that no limb underflows: every
// limb of b is below 2^51 + 2^18, which is less than the limbs of 2p.
func feSub(a, b fieldElement) fieldElement {
	return feCarry(fieldElement{
		a[0] + 0xFFFFFFFFFFFDA - b[0],
		a[1] + 0xFFFFFFFFFFFFE - b[1],
		a[2] + 0xFFFFFFFFFFFFE - b[2],
		a[3] + 0xFFFFFFFFFFFFE - b[3],
		a[4] + 0xFFFFFFFFFFFFE - b[4],
	})
}

// uint128 is an accumulator for sums of 64×64-bit products.
type uint128 struct{ lo, hi uint64 }

func mul64(a, b uint64) uint128 {
	hi, lo := bits.Mul64(a, b)
	return uint128{lo, hi}
}

func addMul64(v uint128, a, b uint64) uint128 {
	hi, lo := bits.Mul64(a, b)
	lo, c := bits.Add64(lo, v.lo, 0)
	hi, _ = bits.Add64(hi, v.hi, c)
	return uint128{lo, hi}
}

func shiftRightBy51(v uint128) uint64 {
	return v.hi<<13 | v.lo>>51
}

// feMul computes a·b. With input limbs below 2^51 + 2^18 each column sum is
// below 2^109, so its carry is below 2^58 and 19 times the top carry still
// fits in 64 bits.
func feMul(a, b fieldElement) fieldElement {
	a1x19 := a[1] * 19
	a2x19 := a[2] * 19
	a3x19 := a[3] * 19
	a4x19 := a[4] * 19

	// r0 = a0b0 + 19(a1b4 + a2b3 + a3b2 + a4b1)
	r0 := mul64(a[0], b[0])
	r0 = addMul64(r0, a1x19, b[4])
	r0 = addMul64(r0, a2x19, b[3])
	r0 = addMul64(r0, a3x19, b[2])
	r0 = addMul64(r0, a4x19, b[1])

	// r1 = a0b1 + a1b0 + 19(a2b4 + a3b3 + a4b2)
	r1 := mul64(a[0], b[1])
	r1 = addMul64(r1, a[1], b[0])
	r1 = addMul64(r1, a2x19, b[4])
	r1 = addMul64(r1, a3x19, b[3])
	r1 = addMul64(r1, a4x19, b[2])

	// r2 = a0b2 + a1b1 + a2b0 + 19(a3b4 + a4b3)
	r2 := mul64(a[0], b[2])
	r2 = addMul64(r2, a[1], b[1])
	r2 = addMul64(r2, a[2], b[0])
	r2 = addMul64(r2, a3x19, b[4])
	r2 = addMul64(r2, a4x19, b[3])

	// r3 = a0b3 + a1b2 + a2b1 + a3b0 + 19·a4b4
	r3 := mul64(a[0], b[3])
	r3 = addMul64(r3, a[1], b[2])
	r3 = addMul64(r3, a[2], b[1])
	r3 = addMul64(r3, a[3], b[0])
	r3 = addMul64(r3, a4x19, b[4])

	// r4 = a0b4 + a1b3 + a2b2 + a3b1 + a4b0
	r4 := mul64(a[0], b[4])
	r4 = addMul64(r4, a[1], b[3])
	r4 = addMul64(r4, a[2], b[2])
	r4 = addMul64(r4, a[3], b[1])
	r4 = addMul64(r4, a[4], b[0])

	c0 := shiftRightBy51(r0)
	c1 := shiftRightBy51(r1)
	c2 := shiftRightBy51(r2)
	c3 := shiftRightBy51(r3)
	c4 := shiftRightBy51(r4)

	return feCarry(fieldElement{
		r0.lo&maskLow51 + c4*19,
		r1.lo&maskLow51 + c0,
		r2.lo&maskLow51 + c1,
		r3.lo&maskLow51 + c2,
		r4.lo&maskLow51 + c3,
	})
}

func feSquare(a fieldElement) fieldElement {
	return feMul(a, a)
}

// feSquareN squares a n times; n is a public constant of the inversion chain.
func feSquareN(a fieldElement, n int) fieldElement {
	for i := 0; i < n; i++ {
		a = feMul(a, a)
	}
	return a
}

// feMul121665 computes a·121665, the (A - 2)/4 constant of Curve25519.
func feMul121665(a fieldElement) fieldElement {
	var lo, c [5]uint64
	for i := range a {
		h, l := bits.Mul64(a[i], 121665)
		lo[i] = l & maskLow51
		c[i] = h<<13 | l>>51
	}
	return feCarry(fieldElement{
		lo[0] + c[4]*19,
		lo[1] + c[0],
		lo[2] + c[1],
		lo[3] + c[2],
		lo[4] + c[3],
	})
}

// feInvert computes z^(p-2) = z^(2^255 - 21), which is 1/z for z ≠ 0 and 0
// for z = 0, with a fixed chain of squarings and multiplications.
func feInvert(z fieldElement) fieldElement {
	z2 := feSquare(z)                  // 2
	z9 := feMul(feSquareN(z2, 2), z)   // 9
	z11 := feMul(z9, z2)               // 11
	z2_5_0 := feMul(feSquare(z11), z9) // 2^5 - 1
	z2_10_0 := feMul(feSquareN(z2_5_0, 5), z2_5_0)
	z2_20_0 := feMul(feSquareN(z2_10_0, 10), z2_10_0)
	z2_40_0 := feMul(feSquareN(z2_20_0, 20), z2_20_0)
	z2_50_0 := feMul(feSquareN(z2_40_0, 10), z2_10_0)
	z2_100_0 := feMul(feSquareN(z2_50_0, 50), z2_50_0)
	z2_200_0 := feMul(feSquareN(z2_100_0, 100), z2_100_0)
	z2_250_0 := feMul(feSquareN(z2_200_0, 50), z2_50_0)
	return feMul(feSquareN(z2_250_0, 5), z11) // 2^255 - 32 + 11
}

// feCondSwap swaps a and b when swap is 1 and leaves them when it is 0,
// without branching on swap.
func feCondSwap(a, b *fieldElement, swap uint64) {
	mask := -swap
	for i := range a {
		t := mask & (a[i] ^ b[i])
		a[i] ^= t
		b[i] ^= t
	}
}

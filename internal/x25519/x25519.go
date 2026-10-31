// Package x25519 implements the X25519 function of RFC 7748 with a
// constant-time Montgomery ladder over GF(2^255 - 19).
package x25519

import (
	"crypto/subtle"
	"errors"
)

// ErrZeroSharedSecret is returned when the result is all zeros, which
// happens when the peer's point has small order. WireGuard rejects it.
var ErrZeroSharedSecret = errors.New("x25519: all-zero shared secret")

var basePoint = [32]byte{9}

// X25519 returns the u-coordinate of scalar·point after clamping the
// scalar, as defined in RFC 7748 §5. It returns ErrZeroSharedSecret, and a
// zero result, when the output is all zeros.
func X25519(scalar, point [32]byte) ([32]byte, error) {
	out := scalarMult(&scalar, &point)
	var acc byte
	for _, b := range out {
		acc |= b
	}
	if subtle.ConstantTimeByteEq(acc, 0) == 1 {
		return [32]byte{}, ErrZeroSharedSecret
	}
	return out, nil
}

// PublicKey returns X25519(private, 9). A clamped scalar is never a
// multiple of the base point's order, so the result is never zero.
func PublicKey(private [32]byte) [32]byte {
	return scalarMult(&private, &basePoint)
}

// scalarMult is the ladder of RFC 7748 §5. The scalar bits only feed the
// conditional swap mask, so neither the control flow nor the memory access
// pattern depends on them.
func scalarMult(scalar, point *[32]byte) [32]byte {
	k := *scalar
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64

	x1 := feFromBytes(point)
	x2 := fieldElement{1}
	var z2 fieldElement
	x3 := x1
	z3 := fieldElement{1}
	var swap uint64

	for t := 254; t >= 0; t-- {
		kt := uint64(k[t>>3]>>(t&7)) & 1
		swap ^= kt
		feCondSwap(&x2, &x3, swap)
		feCondSwap(&z2, &z3, swap)
		swap = kt

		a := feAdd(x2, z2)
		aa := feSquare(a)
		b := feSub(x2, z2)
		bb := feSquare(b)
		e := feSub(aa, bb)
		c := feAdd(x3, z3)
		d := feSub(x3, z3)
		da := feMul(d, a)
		cb := feMul(c, b)
		x3 = feSquare(feAdd(da, cb))
		z3 = feMul(x1, feSquare(feSub(da, cb)))
		x2 = feMul(aa, bb)
		z2 = feMul(e, feAdd(aa, feMul121665(e)))
	}
	feCondSwap(&x2, &x3, swap)
	feCondSwap(&z2, &z3, swap)

	return feToBytes(feMul(x2, feInvert(z2)))
}

// Package noise implements the WireGuard protocol messages, the
// Noise_IKpsk2 handshake, mac1/mac2 and cookie replies, TAI64N timestamps,
// the anti-replay window and transport encryption, as on
// https://www.wireguard.com/protocol/ and in the Linux kernel.
//
// It is a sans-IO core: it never reads a clock, opens a socket or starts a
// goroutine. Callers pass the monotonic time now (nanoseconds), the wall
// time for TAI64N (Unix nanoseconds) and an io.Reader for randomness.
package noise

import (
	"errors"
	"io"

	"github.com/CesarManzoCode/malla-wg/internal/blake2s"
	"github.com/CesarManzoCode/malla-wg/internal/chachapoly"
)

// Protocol constants of https://www.wireguard.com/protocol/.
const (
	// Construction is CONSTRUCTION.
	Construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	// Identifier is IDENTIFIER.
	Identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	// LabelMAC1 is LABEL_MAC1.
	LabelMAC1 = "mac1----"
	// LabelCookie is LABEL_COOKIE.
	LabelCookie = "cookie--"
)

// Message types: the first byte of every message, followed by three zeros.
const (
	TypeInitiation  = 1
	TypeResponse    = 2
	TypeCookieReply = 3
	TypeTransport   = 4
)

// KeySize is the size of X25519 keys, the preshared key and the hash.
const KeySize = 32

// RejectAfterMessages is REJECT_AFTER_MESSAGES: 2^64 - 2^13 - 1.
const RejectAfterMessages uint64 = 1<<64 - 1<<13 - 1

// Times in nanoseconds, from the kernel's messages.h and noise.c.
const (
	cookieSecretMaxAge  int64 = 120e9 // COOKIE_SECRET_MAX_AGE
	cookieSecretLatency int64 = 5e9   // COOKIE_SECRET_LATENCY
	floodInterval       int64 = 1e9 / 50
)

var (
	ErrMessageSize     = errors.New("noise: wrong message size")
	ErrMessageType     = errors.New("noise: wrong message type or nonzero reserved bytes")
	ErrDecrypt         = errors.New("noise: authentication failed")
	ErrUnknownPeer     = errors.New("noise: unknown peer static key")
	ErrStaleTimestamp  = errors.New("noise: initiation timestamp not newer than the last accepted")
	ErrFlood           = errors.New("noise: initiation too soon after the last accepted")
	ErrHandshakeState  = errors.New("noise: message not expected in this handshake state")
	ErrIndex           = errors.New("noise: receiver index does not match")
	ErrNoMAC1Sent      = errors.New("noise: cookie reply without a pending mac1")
	ErrReplay          = errors.New("noise: counter replayed, outside the window or over the limit")
	ErrCounterExceeded = errors.New("noise: sending counter exhausted")
)

var (
	// initialChainKey is HASH(CONSTRUCTION).
	initialChainKey = blake2s.Sum256([]byte(Construction))
	// initialHash is HASH(HASH(CONSTRUCTION) || IDENTIFIER), before the
	// responder's static key is mixed in.
	initialHash = hash(initialChainKey[:], []byte(Identifier))
	zeroNonce   [chachapoly.NonceSize]byte
)

// hash is HASH(parts[0] || parts[1] || …) with BLAKE2s-256.
func hash(parts ...[]byte) [KeySize]byte {
	h := blake2s.New256()
	for _, p := range parts {
		h.Write(p)
	}
	var out [KeySize]byte
	h.Sum(out[:0])
	return out
}

// mixHash sets h to HASH(h || data).
func mixHash(h *[KeySize]byte, data []byte) {
	*h = hash(h[:], data)
}

// seal writes AEAD(key, 0, plaintext, ad) to dst, which must be exactly
// len(plaintext) + 16 bytes. Key and nonce sizes are fixed, so Seal cannot
// fail.
func seal(dst []byte, key, ad *[KeySize]byte, plaintext []byte) {
	out, _ := chachapoly.Seal(nil, key[:], zeroNonce[:], plaintext, ad[:])
	copy(dst, out)
}

// open writes the plaintext of AEAD(key, 0, ·, ad) to dst.
func open(dst []byte, key, ad *[KeySize]byte, ciphertext []byte) error {
	out, err := chachapoly.Open(nil, key[:], zeroNonce[:], ciphertext, ad[:])
	if err != nil {
		return ErrDecrypt
	}
	copy(dst, out)
	return nil
}

// GeneratePrivateKey reads 32 bytes from rnd and clamps them as an X25519
// private key (RFC 7748 §5).
func GeneratePrivateKey(rnd io.Reader) ([KeySize]byte, error) {
	var k [KeySize]byte
	if _, err := io.ReadFull(rnd, k[:]); err != nil {
		return k, err
	}
	k[0] &= 248
	k[31] = k[31]&127 | 64
	return k, nil
}

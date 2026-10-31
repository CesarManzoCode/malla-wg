package noise

import (
	"encoding/binary"

	"github.com/CesarManzoCode/malla-wg/internal/blake2s"
	"github.com/CesarManzoCode/malla-wg/internal/chachapoly"
)

// Keypair holds the transport keys of one session, its sending counter and
// its receive window.
type Keypair struct {
	send, recv  [KeySize]byte
	LocalIndex  uint32
	RemoteIndex uint32
	Initiator   bool
	sendCounter uint64
	replay      ReplayFilter
}

// Sent returns the number of messages encrypted so far, which is the next
// counter.
func (k *Keypair) Sent() uint64 { return k.sendCounter }

// KeyIDs returns the BLAKE2s-256 digests of the sending and receiving keys,
// so that the two ends of a session can be matched without exposing them.
func (k *Keypair) KeyIDs() (send, recv [32]byte) {
	return blake2s.Sum256(k.send[:]), blake2s.Sum256(k.recv[:])
}

// transportNonce is 4 zero bytes followed by the 64-bit little-endian
// counter.
func transportNonce(counter uint64) [chachapoly.NonceSize]byte {
	var n [chachapoly.NonceSize]byte
	binary.LittleEndian.PutUint64(n[4:], counter)
	return n
}

// paddingLen follows the kernel's calculate_skb_padding: pad to a multiple
// of 16, but not beyond mtu when mtu > 0.
func paddingLen(n, mtu int) int {
	if mtu <= 0 {
		return -n & (PaddingMultiple - 1)
	}
	last := n
	if last > mtu {
		last %= mtu
	}
	padded := min(mtu, (last+PaddingMultiple-1)&^(PaddingMultiple-1))
	return padded - last
}

// Encrypt pads packet with zeros and encrypts it under the next counter. An
// empty packet is a keepalive.
func (k *Keypair) Encrypt(packet []byte, mtu int) (*Transport, error) {
	if k.sendCounter >= RejectAfterMessages {
		return nil, ErrCounterExceeded
	}
	counter := k.sendCounter
	k.sendCounter++
	n := len(packet) + paddingLen(len(packet), mtu)
	plain := make([]byte, n, n+chachapoly.Overhead)
	copy(plain, packet)
	nonce := transportNonce(counter)
	ct, err := chachapoly.Seal(plain[:0], k.send[:], nonce[:], plain, nil)
	if err != nil {
		return nil, err
	}
	return &Transport{Receiver: k.RemoteIndex, Counter: counter, Content: ct}, nil
}

// Decrypt authenticates and decrypts m, appending the padded packet to dst.
// The counter goes through the replay window only after the tag verifies,
// so a forged message cannot move the window.
func (k *Keypair) Decrypt(dst []byte, m *Transport) ([]byte, error) {
	if m.Receiver != k.LocalIndex {
		return nil, ErrIndex
	}
	if len(m.Content) < chachapoly.Overhead {
		return nil, ErrMessageSize
	}
	nonce := transportNonce(m.Counter)
	out, err := chachapoly.Open(dst, k.recv[:], nonce[:], m.Content, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	if !k.replay.ValidateCounter(m.Counter, RejectAfterMessages) {
		return nil, ErrReplay
	}
	return out, nil
}

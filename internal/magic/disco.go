package magic

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/CesarManzoCode/malla-wg/internal/blake2s"
	"github.com/CesarManzoCode/malla-wg/internal/chachapoly"
	"github.com/CesarManzoCode/malla-wg/internal/hkdf"
	"github.com/CesarManzoCode/malla-wg/internal/x25519"
)

// DiscoMagic starts every disco datagram. WireGuard messages start with a
// type of 1 to 4 and three zeros, so the two never share a prefix on the
// node's socket (contract §3.3).
const DiscoMagic = "mallaDSC"

// discoInfo is the HKDF info of the disco key.
const discoInfo = "malla disco v1"

// Disco message types and the only version.
const (
	DiscoPing        uint8 = 1
	DiscoPong        uint8 = 2
	DiscoCallMeMaybe uint8 = 3

	discoVersion uint8 = 1
)

const (
	discoKeyLen    = 32
	discoNonceLen  = chachapoly.NonceSizeX
	discoHeaderLen = len(DiscoMagic) + discoKeyLen + discoNonceLen
	discoAddrLen   = 18
	txidLen        = 12
)

var (
	ErrNotDisco    = errors.New("magic: not a disco datagram")
	ErrDiscoOpen   = errors.New("magic: disco datagram does not authenticate")
	ErrDiscoFormat = errors.New("magic: malformed disco message")
)

// IsDisco reports whether b is a disco datagram.
func IsDisco(b []byte) bool {
	return len(b) >= discoHeaderLen && bytes.HasPrefix(b, []byte(DiscoMagic))
}

// DiscoSender returns the disco public key a disco datagram claims to
// come from; only opening it proves the claim.
func DiscoSender(b []byte) ([32]byte, bool) {
	if !IsDisco(b) {
		return [32]byte{}, false
	}
	return [32]byte(b[len(DiscoMagic) : len(DiscoMagic)+discoKeyLen]), true
}

// DiscoSharedKey is the AEAD key between the disco private key priv and
// the peer's disco public key: HKDF-BLAKE2s with an empty salt over
// X25519(priv, peer) and info "malla disco v1". Both sides derive the
// same key.
func DiscoSharedKey(priv, peer [32]byte) ([32]byte, error) {
	shared, err := x25519.X25519(priv, peer)
	if err != nil {
		return [32]byte{}, err
	}
	prk := hkdf.Extract(blake2s.New256, nil, shared[:])
	okm, err := hkdf.Expand(blake2s.New256, prk, []byte(discoInfo), 32)
	if err != nil {
		return [32]byte{}, err
	}
	return [32]byte(okm), nil
}

// Message is a disco message. Ping uses TxID and NodeKey, Pong uses TxID
// and Addr (where the ping came from), CallMeMaybe uses Addrs.
type Message struct {
	Type    uint8
	TxID    [12]byte
	NodeKey [32]byte
	Addr    netip.AddrPort
	Addrs   []netip.AddrPort
}

// AppendBinary appends the plaintext of m: type, version 1 and the body.
func (m Message) AppendBinary(b []byte) ([]byte, error) {
	b = append(b, m.Type, discoVersion)
	switch m.Type {
	case DiscoPing:
		b = append(b, m.TxID[:]...)
		return append(b, m.NodeKey[:]...), nil
	case DiscoPong:
		b = append(b, m.TxID[:]...)
		return appendAddr(b, m.Addr), nil
	case DiscoCallMeMaybe:
		if len(m.Addrs) > 255 {
			return nil, ErrDiscoFormat
		}
		b = append(b, uint8(len(m.Addrs)))
		for _, a := range m.Addrs {
			b = appendAddr(b, a)
		}
		return b, nil
	}
	return nil, ErrDiscoFormat
}

// ParseMessage decodes a plaintext; its length must match its type
// exactly.
func ParseMessage(b []byte) (Message, error) {
	var m Message
	if len(b) < 2 || b[1] != discoVersion {
		return m, ErrDiscoFormat
	}
	m.Type, b = b[0], b[2:]
	switch m.Type {
	case DiscoPing:
		if len(b) != txidLen+32 {
			return m, ErrDiscoFormat
		}
		m.TxID, m.NodeKey = [12]byte(b), [32]byte(b[txidLen:])
	case DiscoPong:
		if len(b) != txidLen+discoAddrLen {
			return m, ErrDiscoFormat
		}
		m.TxID, m.Addr = [12]byte(b), parseAddr(b[txidLen:])
	case DiscoCallMeMaybe:
		if len(b) < 1 || len(b) != 1+int(b[0])*discoAddrLen {
			return m, ErrDiscoFormat
		}
		for i := range int(b[0]) {
			m.Addrs = append(m.Addrs, parseAddr(b[1+i*discoAddrLen:]))
		}
	default:
		return m, ErrDiscoFormat
	}
	return m, nil
}

// appendAddr appends a as a 16-byte (IPv4-mapped) address and a
// big-endian port, as the reflexive service does.
func appendAddr(b []byte, a netip.AddrPort) []byte {
	ip := a.Addr().As16()
	b = append(b, ip[:]...)
	return binary.BigEndian.AppendUint16(b, a.Port())
}

func parseAddr(b []byte) netip.AddrPort {
	ip := netip.AddrFrom16([16]byte(b[:16])).Unmap()
	return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[16:discoAddrLen]))
}

// SealDisco frames m from the node with disco public key sender: magic,
// sender, nonce and m sealed with XChaCha20-Poly1305 under key (see
// DiscoSharedKey). The magic and the sender are the associated data.
func SealDisco(key *[32]byte, sender [32]byte, nonce [24]byte, m Message) ([]byte, error) {
	plain, err := m.AppendBinary(nil)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, discoHeaderLen+len(plain)+chachapoly.Overhead)
	b = append(b, DiscoMagic...)
	b = append(b, sender[:]...)
	b = append(b, nonce[:]...)
	return chachapoly.XSeal(b, key[:], nonce[:], plain, b[:len(DiscoMagic)+discoKeyLen])
}

// OpenDisco authenticates a disco datagram under key and decodes it.
func OpenDisco(key *[32]byte, b []byte) (Message, error) {
	if !IsDisco(b) {
		return Message{}, ErrNotDisco
	}
	nonce := b[len(DiscoMagic)+discoKeyLen : discoHeaderLen]
	plain, err := chachapoly.XOpen(nil, key[:], nonce, b[discoHeaderLen:], b[:len(DiscoMagic)+discoKeyLen])
	if err != nil {
		return Message{}, ErrDiscoOpen
	}
	return ParseMessage(plain)
}

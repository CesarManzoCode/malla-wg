package noise

import (
	"encoding/binary"

	"github.com/CesarManzoCode/malla-wg/internal/chachapoly"
)

// Serialized sizes. A transport message is the 16-byte header, the
// plaintext padded to a multiple of 16 and the 16-byte tag.
const (
	InitiationSize      = 148
	ResponseSize        = 92
	CookieReplySize     = 64
	TransportHeaderSize = 16
	TransportMinSize    = TransportHeaderSize + chachapoly.Overhead
	PaddingMultiple     = 16

	macsSize = 32 // mac1 and mac2 close initiations and responses
)

// Initiation is handshake message 1.
type Initiation struct {
	Sender    uint32
	Ephemeral [KeySize]byte
	Static    [KeySize + chachapoly.Overhead]byte
	Timestamp [TimestampSize + chachapoly.Overhead]byte
	MAC1      [16]byte
	MAC2      [16]byte
}

// Response is handshake message 2.
type Response struct {
	Sender    uint32
	Receiver  uint32
	Ephemeral [KeySize]byte
	Empty     [chachapoly.Overhead]byte
	MAC1      [16]byte
	MAC2      [16]byte
}

// CookieReply is message 3.
type CookieReply struct {
	Receiver uint32
	Nonce    [chachapoly.NonceSizeX]byte
	Cookie   [16 + chachapoly.Overhead]byte
}

// Transport is message 4. Content is the encrypted, padded packet with its
// tag.
type Transport struct {
	Receiver uint32
	Counter  uint64
	Content  []byte
}

// MessageType returns the type of a datagram if its header is valid and its
// size fits that type, and 0 otherwise. The type field is a little-endian
// uint32, so the three reserved bytes must be zero.
func MessageType(b []byte) int {
	if len(b) < 4 || b[1]|b[2]|b[3] != 0 {
		return 0
	}
	switch t := int(b[0]); t {
	case TypeInitiation:
		return sized(t, len(b) == InitiationSize)
	case TypeResponse:
		return sized(t, len(b) == ResponseSize)
	case TypeCookieReply:
		return sized(t, len(b) == CookieReplySize)
	case TypeTransport:
		return sized(t, len(b) >= TransportMinSize)
	}
	return 0
}

func sized(t int, ok bool) int {
	if ok {
		return t
	}
	return 0
}

func putHeader(b []byte, typ byte) {
	b[0], b[1], b[2], b[3] = typ, 0, 0, 0
}

func checkHeader(b []byte, typ byte) error {
	if MessageType(b) == int(typ) {
		return nil
	}
	if len(b) >= 4 && b[0] == typ && b[1]|b[2]|b[3] == 0 {
		return ErrMessageSize
	}
	return ErrMessageType
}

// MarshalBinary returns the 148-byte wire form.
func (m *Initiation) MarshalBinary() ([]byte, error) {
	b := make([]byte, InitiationSize)
	putHeader(b, TypeInitiation)
	binary.LittleEndian.PutUint32(b[4:8], m.Sender)
	copy(b[8:40], m.Ephemeral[:])
	copy(b[40:88], m.Static[:])
	copy(b[88:116], m.Timestamp[:])
	copy(b[116:132], m.MAC1[:])
	copy(b[132:148], m.MAC2[:])
	return b, nil
}

// UnmarshalBinary parses the 148-byte wire form.
func (m *Initiation) UnmarshalBinary(b []byte) error {
	if err := checkHeader(b, TypeInitiation); err != nil {
		return err
	}
	m.Sender = binary.LittleEndian.Uint32(b[4:8])
	copy(m.Ephemeral[:], b[8:40])
	copy(m.Static[:], b[40:88])
	copy(m.Timestamp[:], b[88:116])
	copy(m.MAC1[:], b[116:132])
	copy(m.MAC2[:], b[132:148])
	return nil
}

// MarshalBinary returns the 92-byte wire form.
func (m *Response) MarshalBinary() ([]byte, error) {
	b := make([]byte, ResponseSize)
	putHeader(b, TypeResponse)
	binary.LittleEndian.PutUint32(b[4:8], m.Sender)
	binary.LittleEndian.PutUint32(b[8:12], m.Receiver)
	copy(b[12:44], m.Ephemeral[:])
	copy(b[44:60], m.Empty[:])
	copy(b[60:76], m.MAC1[:])
	copy(b[76:92], m.MAC2[:])
	return b, nil
}

// UnmarshalBinary parses the 92-byte wire form.
func (m *Response) UnmarshalBinary(b []byte) error {
	if err := checkHeader(b, TypeResponse); err != nil {
		return err
	}
	m.Sender = binary.LittleEndian.Uint32(b[4:8])
	m.Receiver = binary.LittleEndian.Uint32(b[8:12])
	copy(m.Ephemeral[:], b[12:44])
	copy(m.Empty[:], b[44:60])
	copy(m.MAC1[:], b[60:76])
	copy(m.MAC2[:], b[76:92])
	return nil
}

// MarshalBinary returns the 64-byte wire form.
func (m *CookieReply) MarshalBinary() ([]byte, error) {
	b := make([]byte, CookieReplySize)
	putHeader(b, TypeCookieReply)
	binary.LittleEndian.PutUint32(b[4:8], m.Receiver)
	copy(b[8:32], m.Nonce[:])
	copy(b[32:64], m.Cookie[:])
	return b, nil
}

// UnmarshalBinary parses the 64-byte wire form.
func (m *CookieReply) UnmarshalBinary(b []byte) error {
	if err := checkHeader(b, TypeCookieReply); err != nil {
		return err
	}
	m.Receiver = binary.LittleEndian.Uint32(b[4:8])
	copy(m.Nonce[:], b[8:32])
	copy(m.Cookie[:], b[32:64])
	return nil
}

// MarshalBinary returns the 16-byte header followed by Content.
func (m *Transport) MarshalBinary() ([]byte, error) {
	if len(m.Content) < chachapoly.Overhead {
		return nil, ErrMessageSize
	}
	b := make([]byte, TransportHeaderSize+len(m.Content))
	putHeader(b, TypeTransport)
	binary.LittleEndian.PutUint32(b[4:8], m.Receiver)
	binary.LittleEndian.PutUint64(b[8:16], m.Counter)
	copy(b[16:], m.Content)
	return b, nil
}

// UnmarshalBinary parses a transport message of at least 32 bytes. Content
// is a copy, so b may be reused.
func (m *Transport) UnmarshalBinary(b []byte) error {
	if err := checkHeader(b, TypeTransport); err != nil {
		return err
	}
	m.Receiver = binary.LittleEndian.Uint32(b[4:8])
	m.Counter = binary.LittleEndian.Uint64(b[8:16])
	m.Content = append(m.Content[:0], b[16:]...)
	return nil
}

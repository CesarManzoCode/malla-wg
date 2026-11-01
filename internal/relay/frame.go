// Package relay is the HTTPS relay of the mesh (contract §3.2): a TLS 1.3
// server that, after an HTTP Upgrade to malla-relay/1, forwards datagrams
// between nodes identified by their node key, and the node's client.
//
// The frame format and the forwarding rules know nothing of sockets: the
// codec works on byte slices and Core decides, for one frame of one
// connection, which frames go to which connections, so the simulator can
// drive the same rules. Server and Client carry them over TLS.
package relay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Frame types of contract §3.2.
type Type uint8

const (
	TypeClientHello Type = 1 // node_key (32)
	TypeServerHello Type = 2 // empty
	TypeSendPacket  Type = 3 // destination node_key (32) + datagram
	TypeRecvPacket  Type = 4 // source node_key (32) + datagram
	TypeKeepAlive   Type = 5 // empty
	TypePeerGone    Type = 6 // node_key (32)
)

func (t Type) String() string {
	switch t {
	case TypeClientHello:
		return "ClientHello"
	case TypeServerHello:
		return "ServerHello"
	case TypeSendPacket:
		return "SendPacket"
	case TypeRecvPacket:
		return "RecvPacket"
	case TypeKeepAlive:
		return "KeepAlive"
	case TypePeerGone:
		return "PeerGone"
	}
	return fmt.Sprintf("Type(%d)", uint8(t))
}

const (
	// HeaderLen is the size of [type u8][length u32 big-endian].
	HeaderLen = 5
	// KeyLen is the size of a node key.
	KeyLen = 32
	// MaxDatagram bounds the datagram inside a packet frame: the largest
	// UDP payload.
	MaxDatagram = 65535
	// MaxPayload bounds the payload of any frame.
	MaxPayload = KeyLen + MaxDatagram
)

// Errors of the codec.
var (
	ErrTooLarge  = errors.New("relay: frame payload too large")
	ErrMalformed = errors.New("relay: malformed frame")
)

// AppendFrame appends the frame of type t whose payload is the
// concatenation of parts to dst.
func AppendFrame(dst []byte, t Type, parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	dst = append(dst, byte(t))
	dst = binary.BigEndian.AppendUint32(dst, uint32(n))
	for _, p := range parts {
		dst = append(dst, p...)
	}
	return dst
}

// ParseFrame reads one frame from the start of b. It returns the frame's
// type, its payload (aliasing b) and the number of bytes it took; n is 0
// with a nil error when b does not yet hold a whole frame. A length over
// MaxPayload is ErrTooLarge, whatever follows.
func ParseFrame(b []byte) (t Type, payload []byte, n int, err error) {
	if len(b) < HeaderLen {
		return 0, nil, 0, nil
	}
	size := binary.BigEndian.Uint32(b[1:HeaderLen])
	if size > MaxPayload {
		return 0, nil, 0, ErrTooLarge
	}
	end := HeaderLen + int(size)
	if len(b) < end {
		return 0, nil, 0, nil
	}
	return Type(b[0]), b[HeaderLen:end], end, nil
}

// ReadFrame reads one frame from r into buf, which it grows if needed,
// and returns the type, the payload (aliasing the returned buffer) and the
// buffer for the next call.
func ReadFrame(r io.Reader, buf []byte) (Type, []byte, []byte, error) {
	if cap(buf) < HeaderLen {
		buf = make([]byte, 0, 2048)
	}
	hdr := buf[:HeaderLen]
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, buf, err
	}
	size := binary.BigEndian.Uint32(hdr[1:])
	if size > MaxPayload {
		return 0, nil, buf, ErrTooLarge
	}
	t := Type(hdr[0])
	if cap(buf) < HeaderLen+int(size) {
		nb := make([]byte, HeaderLen+int(size))
		copy(nb, hdr)
		buf = nb
	}
	payload := buf[HeaderLen : HeaderLen+int(size)]
	if _, err := io.ReadFull(r, payload); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return 0, nil, buf, err
	}
	return t, payload, buf, nil
}

// SplitPacket splits the payload of a SendPacket or RecvPacket frame into
// the node key and the datagram.
func SplitPacket(payload []byte) (key [KeyLen]byte, datagram []byte, err error) {
	if len(payload) < KeyLen {
		return key, nil, ErrMalformed
	}
	copy(key[:], payload[:KeyLen])
	return key, payload[KeyLen:], nil
}

// ParseKey reads the payload of a ClientHello or PeerGone frame.
func ParseKey(payload []byte) (key [KeyLen]byte, err error) {
	if len(payload) != KeyLen {
		return key, ErrMalformed
	}
	copy(key[:], payload)
	return key, nil
}

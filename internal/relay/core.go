package relay

import (
	"errors"

	"github.com/CesarManzoCode/malla-wg/internal/noise"
)

// discoMagic starts every disco message (contract §3.3).
const discoMagic = "mallaDSC"

// ConnID names one client connection of the relay.
type ConnID uint64

// Out is one encoded frame for the connection To.
type Out struct {
	To    ConnID
	Frame []byte
}

// Result is what Core decides for one input.
type Result struct {
	Out []Out
	// Close lists connections to close: a connection replaced by a newer
	// one with the same node key.
	Close []ConnID
	// Forwarded is the datagram that was forwarded, nil if none; the
	// server writes it to the capture file.
	Forwarded []byte
}

// Errors that make the server close the connection that sent the frame.
var (
	ErrNoHello     = errors.New("relay: frame before ClientHello")
	ErrSecondHello = errors.New("relay: second ClientHello")
	ErrUnexpected  = errors.New("relay: unexpected frame type")
)

// Core is the relay's forwarding state: which connection speaks for which
// node key. It reads no clock, opens no socket and starts no goroutine,
// and it is not safe for concurrent use.
type Core struct {
	byKey map[[KeyLen]byte]ConnID
	keyOf map[ConnID][KeyLen]byte
	// Dropped counts packets that were not forwarded: unknown destination
	// or a datagram that is neither WireGuard nor disco.
	Dropped uint64
}

// NewCore returns an empty relay.
func NewCore() *Core {
	return &Core{byKey: make(map[[KeyLen]byte]ConnID), keyOf: make(map[ConnID][KeyLen]byte)}
}

// Forwardable reports whether b is a datagram the relay forwards: a
// WireGuard message (types 1 to 4, contract §3.3) or a disco message.
// The relay holds no key, so it never sees anything else in clear.
func Forwardable(b []byte) bool {
	return noise.MessageType(b) != 0 || (len(b) >= len(discoMagic) && string(b[:len(discoMagic)]) == discoMagic)
}

// Handle processes one frame that connection id sent. An error means the
// connection broke the protocol and must be closed (then Closed called).
func (c *Core) Handle(id ConnID, t Type, payload []byte) (Result, error) {
	var r Result
	src, hello := c.keyOf[id]
	switch t {
	case TypeClientHello:
		if hello {
			return r, ErrSecondHello
		}
		key, err := ParseKey(payload)
		if err != nil {
			return r, err
		}
		if old, ok := c.byKey[key]; ok {
			delete(c.keyOf, old)
			r.Close = append(r.Close, old)
		}
		c.byKey[key] = id
		c.keyOf[id] = key
		r.Out = append(r.Out, Out{To: id, Frame: AppendFrame(nil, TypeServerHello)})
	case TypeSendPacket:
		if !hello {
			return r, ErrNoHello
		}
		dst, dg, err := SplitPacket(payload)
		if err != nil {
			return r, err
		}
		if len(dg) > MaxDatagram || !Forwardable(dg) {
			c.Dropped++
			return r, nil
		}
		to, ok := c.byKey[dst]
		if !ok {
			c.Dropped++
			r.Out = append(r.Out, Out{To: id, Frame: AppendFrame(nil, TypePeerGone, dst[:])})
			return r, nil
		}
		r.Out = append(r.Out, Out{To: to, Frame: AppendFrame(nil, TypeRecvPacket, src[:], dg)})
		r.Forwarded = dg
	case TypeKeepAlive:
		if !hello {
			return r, ErrNoHello
		}
	default:
		return r, ErrUnexpected
	}
	return r, nil
}

// Closed forgets connection id. A newer connection for the same key is
// left alone.
func (c *Core) Closed(id ConnID) {
	key, ok := c.keyOf[id]
	if !ok {
		return
	}
	delete(c.keyOf, id)
	if c.byKey[key] == id {
		delete(c.byKey, key)
	}
}

// Conns returns how many connections said hello.
func (c *Core) Conns() int { return len(c.keyOf) }

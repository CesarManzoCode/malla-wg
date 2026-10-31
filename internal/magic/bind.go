// Package magic sits between the WireGuard device and the network and
// decides, peer by peer, where each encrypted datagram goes: straight to a
// UDP address (direct) or through the relay. This is its first part: the
// bind and the choice between a confirmed direct address and the relay.
// Disco, hole punching and the migration rules of contract §3.3 come on
// top of it.
//
// The device never sees a real address of a peer the bind manages: it
// gets a pseudo endpoint, unique per peer, and the bind translates both
// ways. The device's session therefore does not depend on the path, and
// switching paths changes only where the bind sends.
//
// Like the device, Bind reads no clock, opens no socket and starts no
// goroutine; the runtime calls it from its event loop.
package magic

import (
	"net/netip"
	"slices"

	"github.com/CesarManzoCode/malla-wg/internal/noise"
)

// DirectTimeout is how long a direct address stays confirmed after the
// last datagram received from it (the 5 s of contract §3.3).
const DirectTimeout int64 = 5e9

// ProbeInterval spaces the transport datagrams that, while the relay
// carries a peer's traffic, are copied to its direct candidates so that a
// direct path that starts working is noticed. Handshake messages are
// always copied.
const ProbeInterval int64 = 1e9

// pseudoPrefix holds the pseudo endpoints: an IPv6 unique local prefix
// ("malla" in hex) that no real peer uses. Peer n gets pseudoPrefix + n,
// port pseudoPort.
var pseudoPrefix = netip.MustParseAddr("fd6d:616c:6c61::")

const pseudoPort = 1

// Path is how a peer is reached.
type Path uint8

const (
	PathNone   Path = iota // no direct address and no relay
	PathDirect             // a UDP address
	PathRelay              // the relay
)

func (p Path) String() string {
	switch p {
	case PathDirect:
		return "direct"
	case PathRelay:
		return "relay"
	}
	return "none"
}

// Transmit is one datagram to put on the network: through the relay to
// the node RelayTo when Relay is set, else by UDP to Dst.
type Transmit struct {
	Relay   bool
	RelayTo [noise.KeySize]byte
	Dst     netip.AddrPort
	Data    []byte
}

type peerState struct {
	key    [noise.KeySize]byte
	pseudo netip.AddrPort
	// candidates are the direct addresses the map announces.
	candidates []netip.AddrPort
	// direct is the address the peer was last heard from by UDP, and
	// heard when; it is confirmed for DirectTimeout after that.
	direct    netip.AddrPort
	heard     int64
	lastProbe int64
	probed    bool
}

// Bind is the per-peer path state.
type Bind struct {
	peers    []*peerState // order of AddPeer
	byKey    map[[noise.KeySize]byte]*peerState
	byPseudo map[netip.AddrPort]*peerState
	byAddr   map[netip.AddrPort]*peerState
	next     uint64
	relayUp  bool
}

// New returns a bind without peers and without relay.
func New() *Bind {
	return &Bind{
		byKey:    make(map[[noise.KeySize]byte]*peerState),
		byPseudo: make(map[netip.AddrPort]*peerState),
		byAddr:   make(map[netip.AddrPort]*peerState),
	}
}

// IsPseudo reports whether ep is a pseudo endpoint of some bind.
func IsPseudo(ep netip.AddrPort) bool {
	a := ep.Addr().As16()
	p := pseudoPrefix.As16()
	return ep.Addr().Is6() && [8]byte(a[:8]) == [8]byte(p[:8])
}

// AddPeer starts managing the peer with key and the direct candidates the
// map gives it, and returns the pseudo endpoint to configure in the
// device. Adding a known peer only replaces its candidates.
func (b *Bind) AddPeer(key [noise.KeySize]byte, candidates []netip.AddrPort) netip.AddrPort {
	if p := b.byKey[key]; p != nil {
		b.SetCandidates(key, candidates)
		return p.pseudo
	}
	b.next++
	a := pseudoPrefix.As16()
	for i := range 8 {
		a[15-i] = byte(b.next >> (8 * i))
	}
	p := &peerState{key: key, pseudo: netip.AddrPortFrom(netip.AddrFrom16(a), pseudoPort)}
	b.peers = append(b.peers, p)
	b.byKey[key] = p
	b.byPseudo[p.pseudo] = p
	b.SetCandidates(key, candidates)
	return p.pseudo
}

// Has reports whether the bind manages the peer with key.
func (b *Bind) Has(key [noise.KeySize]byte) bool { return b.byKey[key] != nil }

// Pseudo returns the pseudo endpoint of the peer with key.
func (b *Bind) Pseudo(key [noise.KeySize]byte) (netip.AddrPort, bool) {
	p := b.byKey[key]
	if p == nil {
		return netip.AddrPort{}, false
	}
	return p.pseudo, true
}

// SetCandidates replaces the direct candidates of the peer with key. The
// address the peer was last heard from stays, since it was measured.
func (b *Bind) SetCandidates(key [noise.KeySize]byte, candidates []netip.AddrPort) {
	p := b.byKey[key]
	if p == nil {
		return
	}
	for _, c := range p.candidates {
		if b.byAddr[c] == p && c != p.direct {
			delete(b.byAddr, c)
		}
	}
	p.candidates = p.candidates[:0]
	for _, c := range candidates {
		c = netip.AddrPortFrom(c.Addr().Unmap(), c.Port())
		if !c.IsValid() || IsPseudo(c) || slices.Contains(p.candidates, c) {
			continue
		}
		p.candidates = append(p.candidates, c)
		b.byAddr[c] = p
	}
}

// RemovePeer forgets the peer with key.
func (b *Bind) RemovePeer(key [noise.KeySize]byte) {
	p := b.byKey[key]
	if p == nil {
		return
	}
	for a, q := range b.byAddr {
		if q == p {
			delete(b.byAddr, a)
		}
	}
	delete(b.byKey, key)
	delete(b.byPseudo, p.pseudo)
	b.peers = slices.DeleteFunc(b.peers, func(q *peerState) bool { return q == p })
}

// SetRelay records whether the relay connection is up.
func (b *Bind) SetRelay(up bool) { b.relayUp = up }

// RelayUp reports whether the relay connection is up.
func (b *Bind) RelayUp() bool { return b.relayUp }

// FromUDP maps a datagram received by UDP from src to the source the
// device must see: the pseudo endpoint of the peer that src belongs to,
// which also confirms src as that peer's direct address, or src itself if
// it belongs to no peer. A WireGuard datagram from an unknown address
// still reaches the device, which authenticates it; if it roams the peer
// there, the runtime calls Roamed.
func (b *Bind) FromUDP(now int64, src netip.AddrPort, data []byte) netip.AddrPort {
	p := b.byAddr[src]
	if p == nil {
		return src
	}
	if noise.MessageType(data) != 0 {
		p.direct, p.heard = src, now
	}
	return p.pseudo
}

// FromRelay maps a datagram the relay delivered from the node with key
// src to the source the device must see. It reports false for a node the
// bind does not manage or a datagram that is not WireGuard.
func (b *Bind) FromRelay(src [noise.KeySize]byte, data []byte) (netip.AddrPort, bool) {
	p := b.byKey[src]
	if p == nil || noise.MessageType(data) == 0 {
		return netip.AddrPort{}, false
	}
	return p.pseudo, true
}

// Roamed is called when the device authenticated a datagram of the peer
// with key from ep, a real address the bind did not know: ep becomes the
// peer's confirmed direct address. It returns the pseudo endpoint the
// device must go back to, and false if the bind does not manage the peer.
func (b *Bind) Roamed(now int64, key [noise.KeySize]byte, ep netip.AddrPort) (netip.AddrPort, bool) {
	p := b.byKey[key]
	if p == nil {
		return netip.AddrPort{}, false
	}
	if IsPseudo(ep) {
		return p.pseudo, true
	}
	if old := p.direct; old.IsValid() && b.byAddr[old] == p && !slices.Contains(p.candidates, old) {
		delete(b.byAddr, old)
	}
	p.direct, p.heard = ep, now
	b.byAddr[ep] = p
	return p.pseudo, true
}

// confirmed reports whether p's direct address is confirmed at now.
func (p *peerState) confirmed(now int64) bool {
	return p.direct.IsValid() && now-p.heard < DirectTimeout
}

// PathOf returns how the peer with key is reached at now, and the direct
// address when the path is direct.
func (b *Bind) PathOf(now int64, key [noise.KeySize]byte) (Path, netip.AddrPort) {
	p := b.byKey[key]
	switch {
	case p == nil:
		return PathNone, netip.AddrPort{}
	case p.confirmed(now):
		return PathDirect, p.direct
	case b.relayUp:
		return PathRelay, netip.AddrPort{}
	case p.direct.IsValid():
		return PathDirect, p.direct
	case len(p.candidates) > 0:
		return PathDirect, p.candidates[0]
	}
	return PathNone, netip.AddrPort{}
}

// Route turns a datagram the device addressed to dst into what goes on
// the network. A dst that is no pseudo endpoint (a cookie reply to an
// unknown address, say) goes out by UDP unchanged. For a peer:
//
//   - with a confirmed direct address, the datagram goes there only;
//   - otherwise, with the relay up, it goes through the relay, and a copy
//     goes to every direct candidate if it is a handshake message, or a
//     transport message ProbeInterval after the last copy;
//   - with neither, it goes to the last address the peer was heard from,
//     or else to its first candidate, and handshake messages also to the
//     other candidates.
func (b *Bind) Route(now int64, dst netip.AddrPort, data []byte) []Transmit {
	p := b.byPseudo[dst]
	if p == nil {
		if IsPseudo(dst) {
			return nil
		}
		return []Transmit{{Dst: dst, Data: data}}
	}
	if p.confirmed(now) {
		return []Transmit{{Dst: p.direct, Data: data}}
	}
	t := noise.MessageType(data)
	handshake := t == noise.TypeInitiation || t == noise.TypeResponse || t == noise.TypeCookieReply
	var out []Transmit
	targets := p.targets()
	if b.relayUp {
		out = append(out, Transmit{Relay: true, RelayTo: p.key, Data: data})
		if handshake || !p.probed || now-p.lastProbe >= ProbeInterval {
			if !handshake && len(targets) > 0 {
				p.lastProbe, p.probed = now, true
			}
			for _, a := range targets {
				out = append(out, Transmit{Dst: a, Data: data})
			}
		}
		return out
	}
	for i, a := range targets {
		if i == 0 || handshake {
			out = append(out, Transmit{Dst: a, Data: data})
		}
	}
	return out
}

// targets returns the direct addresses to try: the one the peer was last
// heard from first, then the candidates.
func (p *peerState) targets() []netip.AddrPort {
	var t []netip.AddrPort
	if p.direct.IsValid() {
		t = append(t, p.direct)
	}
	for _, c := range p.candidates {
		if c != p.direct {
			t = append(t, c)
		}
	}
	return t
}

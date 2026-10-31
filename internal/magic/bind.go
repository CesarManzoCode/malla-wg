// Package magic sits between the WireGuard device and the network and
// decides, peer by peer, where each encrypted datagram goes: straight to a
// UDP address (direct) or through the relay. It holds the bind, the choice
// between a confirmed direct address and the relay, disco (disco.go) and
// hole punching (punch.go); path choice by RTT and the migration rules of
// contract §3.3 come on top of it.
//
// The device never sees a real address of a peer the bind manages: it
// gets a pseudo endpoint, unique per peer, and the bind translates both
// ways. The device's session therefore does not depend on the path, and
// switching paths changes only where the bind sends.
//
// Like the device, Bind reads no clock, opens no socket and starts no
// goroutine; the runtime calls it from its event loop, and arms a timer
// for NextDeadline.
package magic

import (
	"io"
	"math"
	"net/netip"
	"slices"

	"github.com/CesarManzoCode/malla-wg/internal/noise"
	"github.com/CesarManzoCode/malla-wg/internal/x25519"
)

// Never is what NextDeadline returns when no timer is armed.
const Never int64 = math.MaxInt64

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
	// candidates are the direct addresses the map announces; learned are
	// those disco taught: the addresses of a CallMeMaybe and the observed
	// sources of pings.
	candidates []netip.AddrPort
	learned    []netip.AddrPort
	// direct is the address the peer was last heard from by UDP, and
	// heard when; it is confirmed for DirectTimeout after that.
	direct    netip.AddrPort
	heard     int64
	lastProbe int64
	probed    bool
	// rtt is the round trip of the ping whose pong last confirmed direct.
	rtt int64

	// disco is the peer's disco public key and shared the AEAD key with
	// it; hasDisco is false until the map gives the key.
	disco    [32]byte
	shared   [32]byte
	hasDisco bool

	// Hole punching: punchPending asks the next Tick to start a window;
	// pings go out at nextPing while it is before punchUntil. pings holds
	// the pings awaiting a pong, by txid.
	punchPending bool
	punchUntil   int64
	nextPing     int64
	pings        map[[12]byte]pingSent
}

type pingSent struct {
	dst netip.AddrPort
	at  int64
}

// Bind is the per-peer path state.
type Bind struct {
	peers    []*peerState // order of AddPeer
	byKey    map[[noise.KeySize]byte]*peerState
	byPseudo map[netip.AddrPort]*peerState
	byAddr   map[netip.AddrPort]*peerState
	byDisco  map[[32]byte]*peerState
	next     uint64
	relayUp  bool

	// Disco: off until SetDisco. nodeKey is the node's WireGuard public
	// key, which pings carry; rand gives nonces and txids.
	discoOn   bool
	discoPriv [32]byte
	discoPub  [32]byte
	nodeKey   [noise.KeySize]byte
	rand      io.Reader
	// endpoints are the node's own, sent in CallMeMaybe; exclude is a
	// prefix no learned address may fall in (the mesh's own).
	endpoints []netip.AddrPort
	exclude   netip.Prefix
}

// New returns a bind without peers, without relay and without disco.
func New() *Bind {
	return &Bind{
		byKey:    make(map[[noise.KeySize]byte]*peerState),
		byPseudo: make(map[netip.AddrPort]*peerState),
		byAddr:   make(map[netip.AddrPort]*peerState),
		byDisco:  make(map[[32]byte]*peerState),
	}
}

// SetDisco turns disco on with the node's disco private key, its
// WireGuard public key and a source of randomness for nonces and txids.
// From then on a peer with a disco key has its direct address confirmed
// by pongs, not by any WireGuard datagram.
func (b *Bind) SetDisco(priv [32]byte, nodeKey [noise.KeySize]byte, rand io.Reader) {
	b.discoOn, b.discoPriv, b.nodeKey, b.rand = true, priv, nodeKey, rand
	b.discoPub = x25519.PublicKey(priv)
	for _, p := range b.peers {
		if p.hasDisco {
			b.SetDiscoKey(p.key, p.disco)
		}
	}
}

// DiscoPublic returns the node's disco public key.
func (b *Bind) DiscoPublic() [32]byte { return b.discoPub }

// SetDiscoKey records the disco public key the map gives the peer with
// key. A key whose shared secret is zero leaves the peer without disco.
func (b *Bind) SetDiscoKey(key [noise.KeySize]byte, disco [32]byte) {
	p := b.byKey[key]
	if p == nil {
		return
	}
	if p.hasDisco && b.byDisco[p.disco] == p {
		delete(b.byDisco, p.disco)
	}
	p.disco, p.hasDisco = disco, false
	if !b.discoOn {
		p.hasDisco = true
		return
	}
	shared, err := DiscoSharedKey(b.discoPriv, disco)
	if err != nil {
		return
	}
	p.shared, p.hasDisco = shared, true
	b.byDisco[disco] = p
}

// SetEndpoints records the node's own endpoints, which CallMeMaybe
// carries to peers.
func (b *Bind) SetEndpoints(eps []netip.AddrPort) {
	b.endpoints = slices.Clone(eps[:min(len(eps), 255)])
}

// SetExclude sets a prefix whose addresses never become candidates: the
// mesh's own, which would send the tunnel through itself.
func (b *Bind) SetExclude(prefix netip.Prefix) { b.exclude = prefix }

// discoReady reports whether p can speak disco.
func (b *Bind) discoReady(p *peerState) bool { return b.discoOn && p.hasDisco }

// excluded reports whether a may not be a candidate.
func (b *Bind) excluded(a netip.AddrPort) bool {
	return !a.IsValid() || IsPseudo(a) || a.Addr().IsUnspecified() ||
		(b.exclude.IsValid() && b.exclude.Contains(a.Addr()))
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
// address the peer was last heard from and the learned ones stay, since
// they were measured. A candidate the peer did not have starts a hole
// punching window at the next Tick.
func (b *Bind) SetCandidates(key [noise.KeySize]byte, candidates []netip.AddrPort) {
	p := b.byKey[key]
	if p == nil {
		return
	}
	old := p.candidates
	p.candidates = nil
	for _, c := range candidates {
		c = netip.AddrPortFrom(c.Addr().Unmap(), c.Port())
		if b.excluded(c) || slices.Contains(p.candidates, c) {
			continue
		}
		p.candidates = append(p.candidates, c)
		if !slices.Contains(old, c) {
			p.punchPending = true
		}
	}
	b.reindex(p)
}

// reindex makes byAddr point to p from its direct address, its candidates
// and its learned addresses, and from nothing else.
func (b *Bind) reindex(p *peerState) {
	for a, q := range b.byAddr {
		if q == p {
			delete(b.byAddr, a)
		}
	}
	for _, a := range p.targets() {
		b.byAddr[a] = p
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
	if b.byDisco[p.disco] == p {
		delete(b.byDisco, p.disco)
	}
	delete(b.byKey, key)
	delete(b.byPseudo, p.pseudo)
	b.peers = slices.DeleteFunc(b.peers, func(q *peerState) bool { return q == p })
}

// SetRelay records whether the relay connection is up.
func (b *Bind) SetRelay(up bool) { b.relayUp = up }

// RelayUp reports whether the relay connection is up.
func (b *Bind) RelayUp() bool { return b.relayUp }

// FromUDP maps a WireGuard datagram received by UDP from src to the
// source the device must see: the pseudo endpoint of the peer that src
// belongs to, or src itself if it belongs to no peer. A datagram from an
// unknown address still reaches the device, which authenticates it; if it
// roams the peer there, the runtime calls Roamed. Disco datagrams go to
// DiscoUDP instead.
//
// For a peer without disco a WireGuard datagram confirms src as its
// direct address. With disco only a pong confirms one, and a WireGuard
// datagram from the confirmed address keeps it confirmed.
func (b *Bind) FromUDP(now int64, src netip.AddrPort, data []byte) netip.AddrPort {
	p := b.byAddr[src]
	if p == nil {
		return src
	}
	if noise.MessageType(data) != 0 && (!b.discoReady(p) || (src == p.direct && p.confirmed(now))) {
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
	p.direct, p.heard = ep, now
	b.reindex(p)
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
// heard from first, then the candidates, then the learned addresses.
func (p *peerState) targets() []netip.AddrPort {
	var t []netip.AddrPort
	if p.direct.IsValid() {
		t = append(t, p.direct)
	}
	for _, c := range slices.Concat(p.candidates, p.learned) {
		if !slices.Contains(t, c) {
			t = append(t, c)
		}
	}
	return t
}

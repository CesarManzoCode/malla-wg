package magic

import (
	"math"
	"net/netip"
	"slices"
)

// Path choice (contract §3.3): a direct address is confirmed while its
// last pong is less than DirectTimeout old; the peer goes by the
// confirmed address of lowest RTT, or else by the relay. While a path is
// confirmed a heartbeat pings it every HeartbeatInterval; once none is,
// the peer is back on the relay and punching is retried every PunchRetry.
const (
	HeartbeatInterval int64 = 2e9
	PunchRetry        int64 = 30e9
)

// unknownRTT marks a path confirmed without a measured round trip (a
// WireGuard datagram for a peer without disco, or roaming); any measured
// path is preferred to it.
const unknownRTT int64 = math.MaxInt64

// directPath is a confirmed direct address: last confirmed at at, with
// round trip rtt.
type directPath struct {
	addr netip.AddrPort
	at   int64
	rtt  int64
}

// confirmAddr records that a was confirmed at now with round trip rtt.
// The path moves to the end of p.paths, so that among equal RTTs the most
// recently confirmed wins; expired paths go. A first confirmed path
// starts the heartbeat.
func (p *peerState) confirmAddr(now int64, a netip.AddrPort, rtt int64) {
	if !p.confirmed(now) {
		p.nextBeat = now + HeartbeatInterval
	}
	p.paths = slices.DeleteFunc(p.paths, func(d directPath) bool {
		return d.addr == a || now-d.at >= DirectTimeout
	})
	p.paths = append(p.paths, directPath{addr: a, at: now, rtt: rtt})
	p.direct = a
}

// best returns the confirmed address of lowest RTT at now; among equal
// RTTs, the most recently confirmed.
func (p *peerState) best(now int64) (netip.AddrPort, bool) {
	var best *directPath
	for i := range p.paths {
		d := &p.paths[i]
		if now-d.at >= DirectTimeout {
			continue
		}
		if best == nil || d.rtt <= best.rtt {
			best = d
		}
	}
	if best == nil {
		return netip.AddrPort{}, false
	}
	return best.addr, true
}

// confirmed reports whether p has a confirmed direct address at now.
func (p *peerState) confirmed(now int64) bool {
	_, ok := p.best(now)
	return ok
}

// prunePaths forgets the paths that are no longer confirmed at now.
func (p *peerState) prunePaths(now int64) {
	p.paths = slices.DeleteFunc(p.paths, func(d directPath) bool { return now-d.at >= DirectTimeout })
}

// expiry is when the last confirmed path stops being confirmed.
func (p *peerState) expiry() int64 {
	at := int64(math.MinInt64)
	for _, d := range p.paths {
		at = max(at, d.at)
	}
	return at + DirectTimeout
}

// heartbeat pings every confirmed path of p, so that each stays
// confirmed, and its RTT measured, while pongs come back.
func (b *Bind) heartbeat(now int64, p *peerState) []Transmit {
	p.nextBeat = now + HeartbeatInterval
	var out []Transmit
	for _, d := range p.paths {
		if now-d.at < DirectTimeout {
			out = append(out, b.ping(now, p, d.addr)...)
		}
	}
	return out
}

// PeerStatus is how one peer is reached, for the control socket.
type PeerStatus struct {
	Key [32]byte
	// Path is PathDirect only with a confirmed direct address, PathRelay
	// with the relay up, else PathNone.
	Path     Path
	Endpoint netip.AddrPort // the direct address, with PathDirect
	RTT      int64          // of the direct address, 0 if not measured
}

// Status reports every peer at now, in the order of AddPeer. Unlike
// PathOf, an address that is only tried (no relay, nothing confirmed) is
// not reported as direct.
func (b *Bind) Status(now int64) []PeerStatus {
	out := make([]PeerStatus, 0, len(b.peers))
	for _, p := range b.peers {
		s := PeerStatus{Key: p.key}
		if a, ok := p.best(now); ok {
			s.Path, s.Endpoint = PathDirect, a
			for _, d := range p.paths {
				if d.addr == a && d.rtt != unknownRTT {
					s.RTT = d.rtt
				}
			}
		} else if b.relayUp {
			s.Path = PathRelay
		}
		out = append(out, s)
	}
	return out
}

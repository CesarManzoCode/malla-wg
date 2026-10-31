package magic

import (
	"io"
	"net/netip"
	"slices"
)

// Hole punching (contract §3.3): when a peer gets new endpoints, or sends
// a CallMeMaybe, the node sends a CallMeMaybe through the relay and pings
// every candidate each PunchInterval during PunchWindow. Both sides do the
// same, so each NAT has a mapping open towards the other before the
// other's pings arrive.
const (
	PunchInterval int64 = 250e6
	PunchWindow   int64 = 10e9
)

// maxLearned bounds the addresses disco teaches about one peer; the
// oldest goes first.
const maxLearned = 16

// punching reports whether p's punching window is open at now.
func (p *peerState) punching(now int64) bool { return now < p.punchUntil }

// NextDeadline returns when Tick must run next, or Never. It mirrors the
// cases of Tick: a pending window or probe, the next round of a window,
// the heartbeat or the expiry of the confirmed paths, the retry.
func (b *Bind) NextDeadline() int64 {
	at := Never
	for _, p := range b.peers {
		switch {
		case !b.discoReady(p):
		case p.punchPending || p.probe.IsValid():
			return 0
		case p.nextPing < p.punchUntil:
			at = min(at, p.nextPing)
		case len(p.paths) > 0:
			at = min(at, p.nextBeat, p.expiry())
		case p.punched:
			at = min(at, p.lastPunch+PunchRetry)
		}
	}
	return at
}

// Tick starts the punching windows that new candidates or the retry ask
// for, sends the pings that are due (punching rounds, heartbeats and
// probes) and forgets expired paths, peer by peer in the order of
// AddPeer.
func (b *Bind) Tick(now int64) []Transmit {
	var out []Transmit
	for _, p := range b.peers {
		if !b.discoReady(p) {
			continue
		}
		for id, s := range p.pings {
			if now-s.at >= PunchWindow {
				delete(p.pings, id)
			}
		}
		p.prunePaths(now)
		switch {
		case p.punchPending:
			out = append(out, b.startPunch(now, p)...)
		case p.nextPing < p.punchUntil:
			if now >= p.nextPing {
				out = append(out, b.punchPings(now, p)...)
			}
		case len(p.paths) > 0:
			if now >= p.nextBeat {
				out = append(out, b.heartbeat(now, p)...)
			}
		case p.punched && now >= p.lastPunch+PunchRetry:
			out = append(out, b.startPunch(now, p)...)
		}
		if p.probe.IsValid() {
			if !p.punching(now) && !p.confirmed(now) {
				out = append(out, b.ping(now, p, p.probe)...)
				p.nextProbe = now + PunchInterval
			}
			p.probe = netip.AddrPort{}
		}
	}
	return out
}

// startPunch opens a punching window for p: a CallMeMaybe with the node's
// endpoints through the relay, if it is up, and the first round of pings.
func (b *Bind) startPunch(now int64, p *peerState) []Transmit {
	p.punchPending = false
	p.punchUntil = now + PunchWindow
	p.punched, p.lastPunch = true, now
	var out []Transmit
	if b.relayUp {
		cmm := Message{Type: DiscoCallMeMaybe, Addrs: b.endpoints}
		if frame, ok := b.seal(p, cmm); ok {
			out = append(out, Transmit{Relay: true, RelayTo: p.key, Data: frame})
		}
	}
	return append(out, b.punchPings(now, p)...)
}

// punchPings is the simultaneous send of hole punching: one ping to every
// target of p, and the next round PunchInterval later. Both sides run it
// on their own, one because its candidates changed and the other because
// of the CallMeMaybe; the K3 mutant mutant_nopunch makes only one side
// send here, which an EIM-APDF NAT on each side cannot survive.
func (b *Bind) punchPings(now int64, p *peerState) []Transmit {
	p.nextPing = now + PunchInterval
	var out []Transmit
	for _, dst := range p.targets() {
		out = append(out, b.ping(now, p, dst)...)
	}
	return out
}

// ping sends p one ping to dst and remembers it for the pong; it sends
// nothing if the randomness fails.
func (b *Bind) ping(now int64, p *peerState, dst netip.AddrPort) []Transmit {
	if p.pings == nil {
		p.pings = make(map[[12]byte]pingSent)
	}
	var txid [12]byte
	if _, err := io.ReadFull(b.rand, txid[:]); err != nil {
		return nil
	}
	frame, ok := b.seal(p, Message{Type: DiscoPing, TxID: txid, NodeKey: b.nodeKey})
	if !ok {
		return nil
	}
	p.pings[txid] = pingSent{dst: dst, at: now}
	return []Transmit{{Dst: dst, Data: frame}}
}

// seal frames m for p with a fresh nonce.
func (b *Bind) seal(p *peerState, m Message) ([]byte, bool) {
	var nonce [24]byte
	if _, err := io.ReadFull(b.rand, nonce[:]); err != nil {
		return nil, false
	}
	frame, err := SealDisco(&p.shared, b.discoPub, nonce, m)
	return frame, err == nil
}

// open finds the peer a disco datagram comes from and authenticates it.
func (b *Bind) open(data []byte) (*peerState, Message, bool) {
	sender, ok := DiscoSender(data)
	if !ok || !b.discoOn {
		return nil, Message{}, false
	}
	p := b.byDisco[sender]
	if p == nil || !b.discoReady(p) {
		return nil, Message{}, false
	}
	m, err := OpenDisco(&p.shared, data)
	return p, m, err == nil
}

// DiscoUDP takes a disco datagram received by UDP from src and returns
// what to send in answer:
//
//   - a Ping is answered with a Pong to src, the observed address, which
//     becomes a candidate of the peer;
//   - a Pong to a ping the node sent to src confirms src as the peer's
//     direct address;
//   - a CallMeMaybe is handled as from the relay.
func (b *Bind) DiscoUDP(now int64, src netip.AddrPort, data []byte) []Transmit {
	p, m, ok := b.open(data)
	if !ok {
		return nil
	}
	switch m.Type {
	case DiscoPing:
		if m.NodeKey != p.key {
			return nil
		}
		b.learn(p, src)
		pong, ok := b.seal(p, Message{Type: DiscoPong, TxID: m.TxID, Addr: src})
		if !ok {
			return nil
		}
		return []Transmit{{Dst: src, Data: pong}}
	case DiscoPong:
		b.confirm(now, p, src, m.TxID)
	case DiscoCallMeMaybe:
		return b.callMeMaybe(now, p, m.Addrs)
	}
	return nil
}

// DiscoRelay takes a disco datagram the relay delivered from the node
// with WireGuard key from. Only a CallMeMaybe means something there; the
// sender's disco key must be the one the map gives that node.
func (b *Bind) DiscoRelay(now int64, from [32]byte, data []byte) []Transmit {
	p, m, ok := b.open(data)
	if !ok || p.key != from || m.Type != DiscoCallMeMaybe {
		return nil
	}
	return b.callMeMaybe(now, p, m.Addrs)
}

// callMeMaybe learns the peer's addresses and, unless a window is already
// open, punches back. Not answering a CallMeMaybe inside an open window
// keeps the two sides from sending each other CallMeMaybe forever.
func (b *Bind) callMeMaybe(now int64, p *peerState, addrs []netip.AddrPort) []Transmit {
	for _, a := range addrs {
		b.learn(p, a)
	}
	if p.punching(now) {
		return nil
	}
	return b.startPunch(now, p)
}

// confirm makes src a confirmed direct address of p, with the measured
// RTT, if txid is a ping the node sent to src and the pong came from
// there.
func (b *Bind) confirm(now int64, p *peerState, src netip.AddrPort, txid [12]byte) {
	s, ok := p.pings[txid]
	if !ok || s.dst != src {
		return
	}
	delete(p.pings, txid)
	p.rtt = now - s.at
	p.confirmAddr(now, src, p.rtt)
	b.reindex(p)
}

// learn adds a as a candidate of p, unless it is excluded, already known
// or another peer's.
func (b *Bind) learn(p *peerState, a netip.AddrPort) {
	a = netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
	if b.excluded(a) || slices.Contains(p.targets(), a) {
		return
	}
	if q := b.byAddr[a]; q != nil && q != p {
		return
	}
	if len(p.learned) == maxLearned {
		if b.byAddr[p.learned[0]] == p && p.learned[0] != p.direct && !slices.Contains(p.candidates, p.learned[0]) {
			delete(b.byAddr, p.learned[0])
		}
		p.learned = p.learned[1:]
	}
	p.learned = append(p.learned, a)
	b.byAddr[a] = p
}

// RTT returns the round trip of the ping whose pong last confirmed the
// peer's direct address, 0 if none did.
func (b *Bind) RTT(key [32]byte) int64 {
	if p := b.byKey[key]; p != nil {
		return p.rtt
	}
	return 0
}

package magic

import (
	"net/netip"
	"slices"
	"testing"
)

// pathNet is two disco nodes, a and b, joined by networks without NAT,
// each with its own one-way delay: b's i-th address is reached from a's
// i-th address. blocked drops every UDP datagram, as the router of the
// end-to-end tests does; the relay always delivers.
type pathNet struct {
	a, b    *discoNode
	addrs   map[[32]byte][]netip.AddrPort
	delays  []int64
	blocked bool
	queue   []inflight
	// relaySends and tickPings record when each node sent through the
	// relay (CallMeMaybe: a window opened) and when its Tick sent a
	// ping by UDP.
	relaySends map[[32]byte][]int64
	tickPings  map[[32]byte][]int64
}

func newPathNet(delays ...int64) *pathNet {
	a, b := newDiscoBind(21, 1), newDiscoBind(22, 2)
	link(a, b)
	n := &pathNet{
		a: a, b: b, addrs: map[[32]byte][]netip.AddrPort{}, delays: delays,
		relaySends: map[[32]byte][]int64{}, tickPings: map[[32]byte][]int64{},
	}
	for i := range delays {
		n.addrs[a.key] = append(n.addrs[a.key], netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, byte(i), 1}), 51820))
		n.addrs[b.key] = append(n.addrs[b.key], netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, byte(i), 2}), 51820))
	}
	for _, x := range []*discoNode{a, b} {
		x.b.SetEndpoints(n.addrs[x.key])
		x.b.SetRelay(true)
	}
	a.b.SetCandidates(b.key, n.addrs[b.key])
	b.b.SetCandidates(a.key, n.addrs[a.key])
	return n
}

func (n *pathNet) other(x *discoNode) *discoNode {
	if x == n.a {
		return n.b
	}
	return n.a
}

func (n *pathNet) send(now int64, from *discoNode, ts []Transmit, tick bool) {
	for _, t := range ts {
		if t.Relay {
			n.relaySends[from.key] = append(n.relaySends[from.key], now)
			n.queue = append(n.queue, inflight{at: now + relayDelay, relay: true, relayTo: t.RelayTo, relayFrm: from.key, data: t.Data})
			continue
		}
		i := slices.Index(n.addrs[n.other(from).key], t.Dst)
		if i < 0 {
			continue
		}
		if tick {
			n.tickPings[from.key] = append(n.tickPings[from.key], now)
		}
		n.queue = append(n.queue, inflight{at: now + n.delays[i], src: n.addrs[from.key][i], dst: t.Dst, data: t.Data})
	}
}

func (n *pathNet) deliver(now int64) {
	for i := 0; i < len(n.queue); {
		p := n.queue[i]
		if p.at > now {
			i++
			continue
		}
		n.queue = append(n.queue[:i], n.queue[i+1:]...)
		for _, x := range []*discoNode{n.a, n.b} {
			switch {
			case p.relay && x.key == p.relayTo && IsDisco(p.data):
				n.send(now, x, x.b.DiscoRelay(now, p.relayFrm, p.data), false)
			case !p.relay && !n.blocked && slices.Contains(n.addrs[x.key], p.dst):
				if IsDisco(p.data) {
					n.send(now, x, x.b.DiscoUDP(now, p.src, p.data), false)
				} else {
					x.b.FromUDP(now, p.src, p.data)
				}
			}
		}
	}
}

// run advances the virtual clock from from to to (exclusive) in steps of
// 1 ms, calling each, if set, at every step after the network moved.
func (n *pathNet) run(from, to int64, each func(now int64)) {
	for now := from; now < to; now += 1e6 {
		for _, x := range []*discoNode{n.a, n.b} {
			if x.b.NextDeadline() <= now {
				n.send(now, x, x.b.Tick(now), true)
			}
		}
		n.deliver(now)
		if each != nil {
			each(now)
		}
	}
}

func countIn(ts []int64, from, to int64) int {
	c := 0
	for _, t := range ts {
		if t > from && t <= to {
			c++
		}
	}
	return c
}

func TestPathDirectPreferred(t *testing.T) {
	// Two direct paths: 30 ms and 5 ms one way. Before any pong the peer
	// is on the relay; after punching it is on the faster path.
	n := newPathNet(30e6, 5e6)
	a, b := n.a, n.b
	fast := n.addrs[b.key][1]
	pseudo, _ := a.b.Pseudo(b.key)
	if p, _ := a.b.PathOf(0, b.key); p != PathRelay {
		t.Fatalf("path before any pong = %s, want relay", p)
	}
	if s := a.b.Status(0); len(s) != 1 || s[0].Path != PathRelay || s[0].Key != b.key {
		t.Fatalf("status before any pong = %+v", s)
	}
	n.run(0, 3e9, nil)
	if p, ep := a.b.PathOf(3e9, b.key); p != PathDirect || ep != fast {
		t.Fatalf("path = %s %s, want direct %s (lowest RTT)", p, ep, fast)
	}
	s := a.b.Status(3e9)
	if len(s) != 1 || s[0].Path != PathDirect || s[0].Endpoint != fast || s[0].RTT < 10e6 || s[0].RTT >= 12e6 {
		t.Fatalf("status = %+v, want direct %s with an RTT of about 10 ms", s, fast)
	}

	// Migration: only the destination changed. Everything goes to the
	// fast path, and the relay is still accepted inbound.
	if got := a.b.Route(3e9, pseudo, transport()); len(got) != 1 || got[0].Relay || got[0].Dst != fast {
		t.Fatalf("route on the direct path: %+v", got)
	}
	if src, ok := a.b.FromRelay(b.key, transport()); !ok || src != pseudo {
		t.Fatalf("FromRelay on the direct path = %s %v", src, ok)
	}

	// Long after the window, the heartbeat keeps both paths confirmed:
	// one ping to each every HeartbeatInterval.
	n.run(3e9, 25e9, nil)
	if p, ep := a.b.PathOf(25e9, b.key); p != PathDirect || ep != fast {
		t.Fatalf("path after the window = %s %s, want direct %s", p, ep, fast)
	}
	if c := countIn(n.tickPings[a.key], 12e9, 24e9); c < 10 || c > 14 {
		t.Fatalf("a sent %d heartbeat pings in 12 s, want about 12 (2 paths every 2 s)", c)
	}
	if got := len(a.b.byKey[b.key].paths); got != 2 {
		t.Fatalf("a has %d confirmed paths, want 2", got)
	}
}

func TestPathFallbackAndRetry(t *testing.T) {
	n := newPathNet(5e6)
	a, b := n.a, n.b
	pseudo, _ := a.b.Pseudo(b.key)
	n.run(0, 12e9, nil)
	if p, _ := a.b.PathOf(12e9, b.key); p != PathDirect {
		t.Fatalf("path before blocking = %s, want direct", p)
	}

	// UDP blocked: the heartbeat gets no pong, and the peer is back on
	// the relay DirectTimeout after the last pong, within one heartbeat.
	n.blocked = true
	lost := int64(-1)
	n.run(12e9, 25e9, func(now int64) {
		if p, _ := a.b.PathOf(now, b.key); lost < 0 && p != PathDirect {
			lost = now
		}
	})
	if lost < 12e9+DirectTimeout-HeartbeatInterval-1e6 || lost > 12e9+DirectTimeout+1e6 {
		t.Fatalf("back on the relay at %d, want within (%d, %d]", lost, 12e9+DirectTimeout-HeartbeatInterval, 12e9+DirectTimeout)
	}
	if p, _ := a.b.PathOf(lost, b.key); p != PathRelay {
		t.Fatalf("path after losing the pongs = %s, want relay", p)
	}
	if got := a.b.Route(lost, pseudo, transport()); len(got) == 0 || !got[0].Relay {
		t.Fatalf("route after losing the pongs: %+v", got)
	}

	// Punching is retried every PunchRetry from the last window: a
	// CallMeMaybe at 0, 30 s and 60 s, and nothing confirmed meanwhile.
	direct := false
	n.run(25e9, 71e9, func(now int64) {
		if p, _ := a.b.PathOf(now, b.key); p == PathDirect {
			direct = true
		}
	})
	if direct {
		t.Fatal("a direct path while UDP is blocked")
	}
	if got, want := n.relaySends[a.key], []int64{0, PunchRetry, 2 * PunchRetry}; !slices.Equal(got, want) {
		t.Fatalf("a opened windows at %v, want %v", got, want)
	}

	// UDP opens at 71 s, after the window of 60 s closed, and nothing
	// else carries traffic: the retry at 90 s finds the path.
	n.blocked = false
	at := int64(-1)
	n.run(71e9, 91e9, func(now int64) {
		if p, _ := a.b.PathOf(now, b.key); at < 0 && p == PathDirect {
			at = now
		}
	})
	if at < 3*PunchRetry || at > 3*PunchRetry+20e6 {
		t.Fatalf("direct again at %d, want just after the retry at %d", at, 3*PunchRetry)
	}
}

func TestPathProbeOnWireGuard(t *testing.T) {
	// UDP blocked from the start: the windows fail and the peer is on the
	// relay. Once UDP opens, a WireGuard datagram from b's address (the
	// probe copy b's bind sends while it is on the relay) makes a ping
	// it at the next Tick, and the pong confirms the path long before the
	// retry.
	n := newPathNet(5e6)
	a, b := n.a, n.b
	n.blocked = true
	n.run(0, 12e9, nil)
	pseudo, _ := a.b.Pseudo(b.key)
	if p, _ := a.b.PathOf(12e9, b.key); p != PathRelay {
		t.Fatalf("path with UDP blocked = %s, want relay", p)
	}
	if got := a.b.Route(12e9, pseudo, transport()); len(got) == 0 || !got[0].Relay {
		t.Fatalf("route with UDP blocked: %+v", got)
	}

	n.blocked = false
	src := n.addrs[b.key][0]
	if got := a.b.FromUDP(12e9, src, transport()); got != pseudo {
		t.Fatalf("FromUDP from b's address = %s, want the pseudo endpoint", got)
	}
	if a.b.NextDeadline() != 0 {
		t.Fatal("a WireGuard datagram from a candidate did not ask for a probe")
	}
	out := a.b.Tick(12e9)
	if len(out) != 1 || out[0].Relay || out[0].Dst != src || !IsDisco(out[0].Data) {
		t.Fatalf("probe = %+v, want one ping to %s", out, src)
	}
	n.send(12e9, a, out, true)
	confirmed := int64(-1)
	n.run(12e9+1e6, 13e9, func(now int64) {
		if p, _ := a.b.PathOf(now, b.key); confirmed < 0 && p == PathDirect {
			confirmed = now
		}
	})
	if confirmed < 0 || confirmed > 12e9+20e6 {
		t.Fatalf("direct after the probe at %d, want within 20 ms of 12 s", confirmed)
	}
	if got := a.b.Route(13e9, pseudo, transport()); len(got) != 1 || got[0].Relay || got[0].Dst != src {
		t.Fatalf("route after the probe: %+v", got)
	}
	// Inbound by the relay still reaches the device as the peer.
	if s, ok := a.b.FromRelay(b.key, transport()); !ok || s != pseudo {
		t.Fatalf("FromRelay after migrating = %s %v", s, ok)
	}
	// With the path confirmed, WireGuard datagrams ask for no probe.
	a.b.FromUDP(13e9, src, transport())
	if a.b.byKey[b.key].probe.IsValid() {
		t.Fatal("a probe asked for with the path confirmed")
	}
}

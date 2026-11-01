package device

import (
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/CesarManzoCode/malla-wg/internal/noise"
)

const (
	sec        int64 = 1e9
	testWall   int64 = 1_793_000_000 * 1e9
	maxTickRun       = 1_000_000
)

// node is a device attached to the fake link, with everything it emitted.
type node struct {
	dev    *Device
	addr   netip.AddrPort
	tun    [][]byte
	events []Event
	sent   []sentDatagram
}

type sentDatagram struct {
	at int64
	Datagram
}

type flight struct {
	from, to netip.AddrPort
	data     []byte
}

// link connects nodes with zero latency under a virtual clock. drop, if
// set, discards a datagram as it is emitted.
type link struct {
	t     *testing.T
	now   int64
	nodes []*node
	queue []flight
	drop  func(from *node, d Datagram) bool
}

func (l *link) nodeAt(a netip.AddrPort) *node {
	for _, n := range l.nodes {
		if n.addr == a {
			return n
		}
	}
	return nil
}

func (l *link) absorb(n *node, out Output) {
	n.tun = append(n.tun, out.Packets...)
	n.events = append(n.events, out.Events...)
	for _, d := range out.Datagrams {
		n.sent = append(n.sent, sentDatagram{l.now, d})
		if l.drop != nil && l.drop(n, d) {
			continue
		}
		l.queue = append(l.queue, flight{n.addr, d.Dst, d.Data})
	}
}

func (l *link) flush() {
	for i := 0; len(l.queue) > 0; i++ {
		if i > maxTickRun {
			l.t.Fatal("link: datagrams never stop")
		}
		f := l.queue[0]
		l.queue = l.queue[1:]
		if dst := l.nodeAt(f.to); dst != nil {
			l.absorb(dst, dst.dev.HandleUDP(l.now, f.from, f.data))
		}
	}
}

// runUntil fires every timer up to and including t, delivering datagrams
// as they appear.
func (l *link) runUntil(t int64) {
	l.flush()
	for i := 0; ; i++ {
		if i > maxTickRun {
			l.t.Fatal("link: timers never stop")
		}
		next := Never
		for _, n := range l.nodes {
			next = min(next, n.dev.NextDeadline())
		}
		if next > t {
			break
		}
		l.now = max(l.now, next)
		for _, n := range l.nodes {
			if n.dev.NextDeadline() <= l.now {
				l.absorb(n, n.dev.Tick(l.now))
			}
		}
		l.flush()
	}
	l.now = max(l.now, t)
}

// fromTUN hands pkt to n's TUN side and delivers what follows.
func (l *link) fromTUN(n *node, pkt []byte) {
	l.absorb(n, n.dev.HandleTUN(l.now, pkt))
	l.flush()
}

// Inner addresses of the two test nodes.
var (
	tunA  = netip.MustParseAddr("10.0.0.1")
	tunB  = netip.MustParseAddr("10.0.0.2")
	tunA6 = netip.MustParseAddr("fd00::1")
	tunB6 = netip.MustParseAddr("fd00::2")
)

// newPair returns a link with node a (10.0.0.1, fd00::1) and node b
// (10.0.0.2, fd00::2), each knowing the other's endpoint.
func newPair(t *testing.T, seed uint64, tweak func(a, b *Config)) (l *link, a, b *node) {
	t.Helper()
	keys := rand.NewChaCha8(seedBytes(seed, 0))
	privA, _ := noise.GeneratePrivateKey(keys)
	privB, _ := noise.GeneratePrivateKey(keys)
	pubA, pubB := noise.NewLocal(privA).PublicKey(), noise.NewLocal(privB).PublicKey()
	addrA := netip.MustParseAddrPort("192.0.2.1:51820")
	addrB := netip.MustParseAddrPort("198.51.100.2:51820")
	cfgA := Config{
		PrivateKey: privA,
		Rand:       rand.NewChaCha8(seedBytes(seed, 1)),
		WallOffset: testWall,
		Peers: []PeerConfig{{
			PublicKey:  pubB,
			AllowedIPs: []netip.Prefix{netip.PrefixFrom(tunB, 32), netip.PrefixFrom(tunB6, 128)},
			Endpoint:   addrB,
		}},
	}
	cfgB := Config{
		PrivateKey: privB,
		Rand:       rand.NewChaCha8(seedBytes(seed, 2)),
		WallOffset: testWall + 7*sec,
		Peers: []PeerConfig{{
			PublicKey:  pubA,
			AllowedIPs: []netip.Prefix{netip.PrefixFrom(tunA, 32), netip.PrefixFrom(tunA6, 128)},
			Endpoint:   addrA,
		}},
	}
	if tweak != nil {
		tweak(&cfgA, &cfgB)
	}
	devA, err := New(cfgA)
	if err != nil {
		t.Fatal(err)
	}
	devB, err := New(cfgB)
	if err != nil {
		t.Fatal(err)
	}
	a, b = &node{dev: devA, addr: addrA}, &node{dev: devB, addr: addrB}
	return &link{t: t, nodes: []*node{a, b}}, a, b
}

func seedBytes(seed uint64, stream byte) [32]byte {
	var s [32]byte
	binary.LittleEndian.PutUint64(s[:], seed)
	s[31] = stream
	return s
}

// ip4 builds an IPv4/UDP-like packet with the given payload.
func ip4(src, dst netip.Addr, payload string) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8], b[9] = 64, 17
	s, d := src.As4(), dst.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	copy(b[20:], payload)
	return b
}

// ip6 builds an IPv6 packet with the given payload.
func ip6(src, dst netip.Addr, payload string) []byte {
	b := make([]byte, 40+len(payload))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(len(payload)))
	b[6], b[7] = 17, 64
	s, d := src.As16(), dst.As16()
	copy(b[8:24], s[:])
	copy(b[24:40], d[:])
	copy(b[40:], payload)
	return b
}

// establish has a send a packet to b at the current time: a initiates, b
// responds and receives the packet.
func establish(t *testing.T, l *link, a, b *node) {
	t.Helper()
	before := len(b.tun)
	l.fromTUN(a, ip4(tunA, tunB, "hello"))
	if len(b.tun) != before+1 {
		t.Fatalf("handshake did not deliver the first packet: b got %d packets", len(b.tun)-before)
	}
	pa, pb := a.dev.peers[0], b.dev.peers[0]
	if pa.current == nil || pb.current == nil || !coherent(pa.current, pb.current) {
		t.Fatal("handshake did not leave matching current keypairs")
	}
}

// coherent reports whether x and y are the two ends of one session.
func coherent(x, y *keypair) bool {
	return x.LocalIndex == y.RemoteIndex && x.RemoteIndex == y.LocalIndex && x.Initiator != y.Initiator
}

// initiationTimes returns when n sent initiations, from sent[from:].
func initiationTimes(n *node, from int) []int64 {
	var ts []int64
	for _, s := range n.sent[from:] {
		if noise.MessageType(s.Data) == noise.TypeInitiation {
			ts = append(ts, s.at)
		}
	}
	return ts
}

func hasDrop(events []Event, reason string) bool {
	for _, e := range events {
		if e.Kind == EventDrop && e.Reason == reason {
			return true
		}
	}
	return false
}

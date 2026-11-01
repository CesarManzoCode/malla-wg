package magic

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/CesarManzoCode/malla-wg/internal/noise"
	"github.com/CesarManzoCode/malla-wg/internal/x25519"
)

func discoKeys(t *testing.T, seed byte) (priv, pub [32]byte) {
	t.Helper()
	// The seed goes in byte 1: clamping clears the low three bits of
	// byte 0, which would map small seeds to the same scalar.
	priv[1], priv[31] = seed, 0x40
	return priv, x25519.PublicKey(priv)
}

func TestDiscoSealOpen(t *testing.T) {
	aPriv, aPub := discoKeys(t, 1)
	bPriv, bPub := discoKeys(t, 2)
	_, cPub := discoKeys(t, 3)
	kab, err := DiscoSharedKey(aPriv, bPub)
	if err != nil {
		t.Fatal(err)
	}
	kba, err := DiscoSharedKey(bPriv, aPub)
	if err != nil || kab != kba {
		t.Fatalf("shared keys differ: %x %x %v", kab, kba, err)
	}
	kac, _ := DiscoSharedKey(aPriv, cPub)
	if kac == kab {
		t.Fatal("different peers share a key")
	}
	if _, err := DiscoSharedKey(aPriv, [32]byte{}); err == nil {
		t.Fatal("a zero public key gave a disco key")
	}

	msgs := []Message{
		{Type: DiscoPing, TxID: [12]byte{1, 2, 3}, NodeKey: [32]byte{9, 9}},
		{Type: DiscoPong, TxID: [12]byte{4}, Addr: netip.MustParseAddrPort("203.0.113.7:41641")},
		{Type: DiscoCallMeMaybe, Addrs: []netip.AddrPort{
			netip.MustParseAddrPort("198.51.100.1:51820"), netip.MustParseAddrPort("[2001:db8::1]:7"),
		}},
		{Type: DiscoCallMeMaybe},
	}
	for i, m := range msgs {
		nonce := [24]byte{byte(i), 0xaa}
		frame, err := SealDisco(&kab, aPub, nonce, m)
		if err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
		if !IsDisco(frame) || noise.MessageType(frame) != 0 {
			t.Fatalf("frame %d does not demultiplex as disco", i)
		}
		if s, ok := DiscoSender(frame); !ok || s != aPub {
			t.Fatalf("sender of frame %d = %x", i, s)
		}
		got, err := OpenDisco(&kba, frame)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		if got.Type != m.Type || got.TxID != m.TxID || got.NodeKey != m.NodeKey || got.Addr != m.Addr || len(got.Addrs) != len(m.Addrs) {
			t.Fatalf("message %d: got %+v, want %+v", i, got, m)
		}
		for j := range m.Addrs {
			if got.Addrs[j] != m.Addrs[j] {
				t.Fatalf("message %d addr %d: %s, want %s", i, j, got.Addrs[j], m.Addrs[j])
			}
		}
		if _, err := OpenDisco(&kac, frame); !errors.Is(err, ErrDiscoOpen) {
			t.Fatalf("frame %d opened under the wrong key: %v", i, err)
		}

		// Any altered byte after the magic fails authentication: the
		// sender and the nonce too, since the header is associated data
		// and the nonce feeds the cipher.
		for _, at := range []int{len(DiscoMagic), len(DiscoMagic) + 31, len(DiscoMagic) + 32, discoHeaderLen - 1, discoHeaderLen, len(frame) - 1} {
			bad := bytes.Clone(frame)
			bad[at] ^= 0x01
			if _, err := OpenDisco(&kba, bad); !errors.Is(err, ErrDiscoOpen) {
				t.Fatalf("frame %d altered at %d: %v", i, at, err)
			}
		}
		bad := bytes.Clone(frame)
		bad[0] ^= 0x01
		if _, err := OpenDisco(&kba, bad); !errors.Is(err, ErrNotDisco) {
			t.Fatalf("frame %d with altered magic: %v", i, err)
		}
		if _, err := OpenDisco(&kba, frame[:len(frame)-1]); err == nil {
			t.Fatalf("truncated frame %d opened", i)
		}
	}

	// Plaintexts whose length does not match their type, an unknown type
	// or another version are rejected.
	for _, p := range [][]byte{
		{},
		{DiscoPing, 1},
		append([]byte{DiscoPing, 2}, make([]byte, 44)...),
		append([]byte{DiscoPing, 1}, make([]byte, 45)...),
		append([]byte{DiscoPong, 1}, make([]byte, 29)...),
		{DiscoCallMeMaybe, 1},
		append([]byte{DiscoCallMeMaybe, 1, 2}, make([]byte, 18)...),
		{9, 1},
	} {
		if _, err := ParseMessage(p); !errors.Is(err, ErrDiscoFormat) {
			t.Fatalf("ParseMessage(%x) = %v", p, err)
		}
	}
}

func TestDiscoDemux(t *testing.T) {
	// WireGuard messages and reflexive replies are never disco.
	for _, wg := range [][]byte{initiation(), transport(), append([]byte{2, 0, 0, 0}, make([]byte, 88)...), append([]byte{3, 0, 0, 0}, make([]byte, 60)...)} {
		if IsDisco(wg) {
			t.Fatalf("WireGuard type %d taken as disco", wg[0])
		}
	}
	if IsDisco(append([]byte("mallaSTN"), make([]byte, 100)...)) {
		t.Fatal("a reflexive message taken as disco")
	}
	if IsDisco([]byte(DiscoMagic)) {
		t.Fatal("a bare magic taken as a disco frame")
	}

	// In the bind: disco goes to DiscoUDP/DiscoRelay, never through the
	// paths of WireGuard datagrams.
	a, b := newDiscoBind(1, 1), newDiscoBind(2, 2)
	link(a, b)
	pb := a.b.byKey[b.key]
	ping, ok := a.b.seal(pb, Message{Type: DiscoPing, TxID: [12]byte{7}, NodeKey: a.key})
	if !ok {
		t.Fatal("seal failed")
	}
	if _, ok := b.b.FromRelay(a.key, ping); ok {
		t.Fatal("FromRelay let a disco datagram through to the device")
	}
	src := netip.MustParseAddrPort("192.0.2.10:5000")
	out := b.b.DiscoUDP(0, src, ping)
	if len(out) != 1 || out[0].Relay || out[0].Dst != src || !IsDisco(out[0].Data) {
		t.Fatalf("answer to a ping: %+v", out)
	}
	pong, err := OpenDisco(&b.b.byKey[a.key].shared, out[0].Data)
	if err != nil || pong.Type != DiscoPong || pong.TxID != [12]byte{7} || pong.Addr != src {
		t.Fatalf("pong = %+v, %v", pong, err)
	}
	// The observed source became a candidate: a WireGuard datagram from
	// it now reaches the device as the peer.
	if got := b.b.FromUDP(0, src, transport()); got != b.b.byKey[a.key].pseudo {
		t.Fatalf("FromUDP from the pinged source = %s", got)
	}
	// A ping that claims another node key, or comes from an unknown disco
	// key, gets nothing.
	forged, _ := a.b.seal(pb, Message{Type: DiscoPing, NodeKey: [32]byte{0xee}})
	if out := b.b.DiscoUDP(0, src, forged); out != nil {
		t.Fatalf("answer to a ping with a foreign node key: %+v", out)
	}
	stranger := newDiscoBind(3, 3)
	stranger.b.AddPeer(b.key, nil)
	stranger.b.SetDiscoKey(b.key, b.b.DiscoPublic())
	sp, _ := stranger.b.seal(stranger.b.byKey[b.key], Message{Type: DiscoPing, NodeKey: stranger.key})
	if out := b.b.DiscoUDP(0, src, sp); out != nil {
		t.Fatalf("answer to a stranger: %+v", out)
	}
	// Through the relay, a disco datagram must come from the node the
	// disco key belongs to.
	cmm, _ := a.b.seal(pb, Message{Type: DiscoCallMeMaybe})
	if out := b.b.DiscoRelay(0, [32]byte{0x55}, cmm); out != nil {
		t.Fatalf("CallMeMaybe relayed from another node: %+v", out)
	}
}

func TestEndpoints(t *testing.T) {
	mesh := netip.MustParsePrefix("10.200.0.0/16")
	refl := netip.MustParseAddrPort("203.0.113.9:40001")
	local := []netip.Addr{
		netip.MustParseAddr("192.168.1.5"), netip.MustParseAddr("10.200.0.3"),
		netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("::ffff:192.168.1.5"), netip.MustParseAddr("172.16.0.2"),
	}
	got := Endpoints(refl, local, 51820, mesh)
	want := []netip.AddrPort{refl, netip.MustParseAddrPort("192.168.1.5:51820"), netip.MustParseAddrPort("172.16.0.2:51820")}
	if !EndpointsChanged(nil, got) || EndpointsChanged(got, want) {
		t.Fatalf("Endpoints = %v, want %v", got, want)
	}
	if got := Endpoints(netip.AddrPort{}, local[:1], 51820, mesh); len(got) != 1 || got[0].Port() != 51820 {
		t.Fatalf("without reflexive: %v", got)
	}
	var many []netip.Addr
	for i := range 40 {
		many = append(many, netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}))
	}
	if got := Endpoints(refl, many, 1, mesh); len(got) != MaxEndpoints || got[0] != refl {
		t.Fatalf("cap: %d endpoints, first %v", len(got), got[0])
	}
}

// discoNode is a bind with disco on, as a node of the fake network.
type discoNode struct {
	b   *Bind
	key [32]byte
	// addr is the node's own address; nat the NAT in front of it.
	addr netip.AddrPort
	nat  *fakeNAT
}

func newDiscoBind(seed uint64, id byte) *discoNode {
	rng := rand.NewChaCha8([32]byte{byte(seed), 'd', 'i', 's', 'c', 'o'})
	var priv [32]byte
	rng.Read(priv[:])
	n := &discoNode{b: New(), key: [32]byte{id, 'k'}}
	n.b.SetDisco(priv, n.key, rng)
	return n
}

// link makes a and b peers that know each other's disco key, without
// candidates.
func link(a, b *discoNode) {
	a.b.AddPeer(b.key, nil)
	a.b.SetDiscoKey(b.key, b.b.DiscoPublic())
	b.b.AddPeer(a.key, nil)
	b.b.SetDiscoKey(a.key, a.b.DiscoPublic())
}

// fakeNAT is the minimal EIM-APDF NAT of RFC 4787: an internal endpoint
// keeps one external port whatever the destination (EIM), and a datagram
// from outside passes only if that port already sent to its exact source
// address and port (APDF).
type fakeNAT struct {
	ext     netip.Addr
	byInt   map[netip.AddrPort]uint16
	byExt   map[uint16]netip.AddrPort
	sent    map[uint16]map[netip.AddrPort]bool
	next    uint16
	dropped int
}

func newNAT(ext string) *fakeNAT {
	return &fakeNAT{
		ext: netip.MustParseAddr(ext), byInt: map[netip.AddrPort]uint16{},
		byExt: map[uint16]netip.AddrPort{}, sent: map[uint16]map[netip.AddrPort]bool{}, next: 40000,
	}
}

// mapping returns the external endpoint of in, creating it; the node's
// query to the reflexive service did this before punching starts.
func (n *fakeNAT) mapping(in netip.AddrPort) netip.AddrPort {
	port, ok := n.byInt[in]
	if !ok {
		port, n.next = n.next, n.next+1
		n.byInt[in], n.byExt[port] = port, in
		n.sent[port] = map[netip.AddrPort]bool{}
	}
	return netip.AddrPortFrom(n.ext, port)
}

func (n *fakeNAT) out(src, dst netip.AddrPort) netip.AddrPort {
	ext := n.mapping(src)
	n.sent[ext.Port()][dst] = true
	return ext
}

func (n *fakeNAT) in(src, dst netip.AddrPort) (netip.AddrPort, bool) {
	in, ok := n.byExt[dst.Port()]
	if !ok || !n.sent[dst.Port()][src] {
		n.dropped++
		return netip.AddrPort{}, false
	}
	return in, true
}

// Latencies of the fake network: the relay is slower than UDP, so that a
// first ping reaches the other NAT before the CallMeMaybe makes the other
// side send.
const (
	udpDelay   int64 = 20e6
	relayDelay int64 = 50e6
)

type inflight struct {
	at       int64
	relay    bool
	relayTo  [32]byte
	relayFrm [32]byte
	src, dst netip.AddrPort
	data     []byte
}

type fakeNet struct {
	nodes []*discoNode
	queue []inflight
	pings map[[32]byte]int // pings each node put on the wire
}

func (f *fakeNet) send(now int64, from *discoNode, ts []Transmit) {
	for _, t := range ts {
		if t.Relay {
			f.queue = append(f.queue, inflight{at: now + relayDelay, relay: true, relayTo: t.RelayTo, relayFrm: from.key, data: t.Data})
			continue
		}
		f.pings[from.key]++
		src := from.nat.out(from.addr, t.Dst)
		f.queue = append(f.queue, inflight{at: now + udpDelay, src: src, dst: t.Dst, data: t.Data})
	}
}

// deliver hands over everything due at now, in send order, including
// what the answers send with zero delay left.
func (f *fakeNet) deliver(now int64) {
	for i := 0; i < len(f.queue); {
		p := f.queue[i]
		if p.at > now {
			i++
			continue
		}
		f.queue = append(f.queue[:i], f.queue[i+1:]...)
		for _, n := range f.nodes {
			switch {
			case p.relay && n.key == p.relayTo:
				f.send(now, n, n.b.DiscoRelay(now, p.relayFrm, p.data))
			case !p.relay && n.nat.ext == p.dst.Addr():
				if _, ok := n.nat.in(p.src, p.dst); ok {
					f.send(now, n, n.b.DiscoUDP(now, p.src, p.data))
				}
			}
		}
	}
}

// punch runs two nodes behind EIM-APDF NATs for 12 virtual seconds. The
// map gives a the reflexive address of b if aKnows, and b that of a if
// bKnows; relay says whether the relay is up for CallMeMaybe. It returns
// the nodes, their NATs' external endpoints and when each confirmed the
// other as direct (-1 for never).
func punch(t *testing.T, relay, aKnows, bKnows bool) (a, b *discoNode, extA, extB netip.AddrPort, confA, confB int64) {
	t.Helper()
	a, b = newDiscoBind(11, 1), newDiscoBind(12, 2)
	a.addr, a.nat = netip.MustParseAddrPort("192.168.1.2:51820"), newNAT("203.0.113.1")
	b.addr, b.nat = netip.MustParseAddrPort("192.168.2.2:51820"), newNAT("198.51.100.1")
	extA, extB = a.nat.mapping(a.addr), b.nat.mapping(b.addr)
	link(a, b)
	a.b.SetEndpoints([]netip.AddrPort{extA, a.addr})
	b.b.SetEndpoints([]netip.AddrPort{extB, b.addr})
	a.b.SetRelay(relay)
	b.b.SetRelay(relay)
	if aKnows {
		a.b.SetCandidates(b.key, []netip.AddrPort{extB})
	}
	if bKnows {
		b.b.SetCandidates(a.key, []netip.AddrPort{extA})
	}
	f := &fakeNet{nodes: []*discoNode{a, b}, pings: map[[32]byte]int{}}
	confA, confB = -1, -1
	for now := int64(0); now <= 12e9; now += 1e6 {
		for _, n := range f.nodes {
			if n.b.NextDeadline() <= now {
				f.send(now, n, n.b.Tick(now))
			}
		}
		f.deliver(now)
		if confA < 0 && a.b.byKey[b.key].confirmed(now) {
			confA = now
		}
		if confB < 0 && b.b.byKey[a.key].confirmed(now) {
			confB = now
		}
	}
	// The heartbeat and the retry keep NextDeadline armed after the
	// window (path.go); the window itself must be closed.
	if a.b.byKey[b.key].punching(12e9) || b.b.byKey[a.key].punching(12e9) {
		t.Fatal("a punching window outlived PunchWindow")
	}
	t.Logf("relay=%v aKnows=%v bKnows=%v: pings a=%d b=%d, dropped by NAT a=%d b=%d, confirmed a=%d b=%d",
		relay, aKnows, bKnows, f.pings[a.key], f.pings[b.key], a.nat.dropped, b.nat.dropped, confA, confB)
	return a, b, extA, extB, confA, confB
}

func TestPunchEIMAPDF(t *testing.T) {
	// Only a learns b's endpoint and there is no relay: b never sends, so
	// b's NAT drops every ping of a and nothing is confirmed. The NAT
	// opens only to simultaneous sending.
	a, b, _, _, confA, confB := punch(t, false, true, false)
	if confA >= 0 || confB >= 0 {
		t.Fatalf("one-sided punching confirmed a direct path: %d %d", confA, confB)
	}
	if b.nat.dropped == 0 || len(b.b.byKey[a.key].learned) != 0 {
		t.Fatalf("b's NAT let a's pings in: dropped %d", b.nat.dropped)
	}

	// Both learn the other's endpoint from the map: both punch at once
	// and both confirm within the window.
	a, b, extA, extB, confA, confB := punch(t, false, true, true)
	if confA < 0 || confB < 0 || confA >= PunchWindow || confB >= PunchWindow {
		t.Fatalf("simultaneous punching: confirmed a=%d b=%d", confA, confB)
	}
	if p, ep := a.b.PathOf(confA, b.key); p != PathDirect || ep != extB {
		t.Fatalf("a's path = %s %s, want direct %s", p, ep, extB)
	}
	if p, ep := b.b.PathOf(confB, a.key); p != PathDirect || ep != extA {
		t.Fatalf("b's path = %s %s, want direct %s", p, ep, extA)
	}

	// Only a learns b's endpoint, but the relay carries a's CallMeMaybe:
	// b punches back, b's NAT drops a's first pings, and both confirm.
	a, b, extA, extB, confA, confB = punch(t, true, true, false)
	if confA < 0 || confB < 0 || confA >= PunchWindow || confB >= PunchWindow {
		t.Fatalf("punching after CallMeMaybe: confirmed a=%d b=%d", confA, confB)
	}
	if b.nat.dropped == 0 {
		t.Fatal("b's NAT dropped nothing: the scenario does not need b to send")
	}
	if a.b.byKey[b.key].direct != extB || b.b.byKey[a.key].direct != extA {
		t.Fatalf("direct addresses a→%s b→%s, want %s and %s", a.b.byKey[b.key].direct, b.b.byKey[a.key].direct, extB, extA)
	}
	// b learned a's external endpoint, which the map never gave it.
	if pa := b.b.byKey[a.key]; len(pa.candidates) != 0 || !containsAddr(pa.learned, extA) {
		t.Fatalf("b's candidates %v, learned %v", pa.candidates, pa.learned)
	}
	if a.b.RTT(b.key) <= 0 || b.b.RTT(a.key) <= 0 {
		t.Fatalf("RTT a=%d b=%d", a.b.RTT(b.key), b.b.RTT(a.key))
	}
}

func containsAddr(s []netip.AddrPort, a netip.AddrPort) bool {
	for _, x := range s {
		if x == a {
			return true
		}
	}
	return false
}

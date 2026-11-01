package device

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/CesarManzoCode/malla-wg/internal/noise"
)

func TestAllowedIPsLongestPrefix(t *testing.T) {
	var tbl allowedIPs
	p := make([]*peer, 7)
	for i := range p {
		p[i] = &peer{key: [noise.KeySize]byte{byte(i)}}
	}
	for _, r := range []struct {
		pfx string
		to  *peer
	}{
		{"10.0.0.0/8", p[1]},
		{"10.1.0.0/16", p[2]},
		{"10.1.2.3/32", p[3]},
		{"0.0.0.0/0", p[4]},
		{"fd00::/8", p[5]},
		{"fd00:1::/32", p[6]},
		{"192.168.1.77/24", p[2]}, // host bits are masked
	} {
		tbl.insert(netip.MustParsePrefix(r.pfx), r.to)
	}
	for _, c := range []struct {
		addr string
		want *peer
	}{
		{"10.1.2.3", p[3]},
		{"10.1.2.4", p[2]},
		{"10.2.0.1", p[1]},
		{"11.0.0.1", p[4]},
		{"192.168.1.1", p[2]},
		{"fd00:1::5", p[6]},
		{"fd00:2::1", p[5]},
		{"2001:db8::1", nil},
		{"::ffff:10.1.2.3", nil}, // IPv6 never matches IPv4 prefixes
	} {
		if got := tbl.lookup(netip.MustParseAddr(c.addr)); got != c.want {
			t.Errorf("lookup(%s) = %v, want %v", c.addr, got, c.want)
		}
	}
	tbl.insert(netip.MustParsePrefix("10.1.2.3/32"), p[1])
	if got := tbl.lookup(netip.MustParseAddr("10.1.2.3")); got != p[1] {
		t.Errorf("reinserted prefix still maps to the old peer")
	}
	if got := tbl.lookup(netip.Addr{}); got != nil {
		t.Errorf("lookup of the zero address = %v, want nil", got)
	}
}

func TestDataExchange(t *testing.T) {
	l, a, b := newPair(t, 10, nil)
	establish(t, l, a, b)

	// Odd sizes: the receiver trims the padding by the IP header length.
	pkt4 := ip4(tunB, tunA, "12345")
	l.fromTUN(b, pkt4)
	if len(a.tun) != 1 || !bytes.Equal(a.tun[0], pkt4) {
		t.Fatalf("a received %x, want %x", a.tun, pkt4)
	}
	if got := len(b.sent[len(b.sent)-1].Data); got != noise.TransportHeaderSize+32+16 {
		t.Errorf("25-byte packet travelled as %d bytes, want padding to 32", got)
	}
	pkt6 := ip6(tunA6, tunB6, "xyz")
	l.fromTUN(a, pkt6)
	if got := b.tun[len(b.tun)-1]; !bytes.Equal(got, pkt6) {
		t.Fatalf("b received %x, want %x", got, pkt6)
	}

	for i := range 100 {
		l.runUntil(l.now + 100e6)
		l.fromTUN(a, ip4(tunA, tunB, string(rune('a'+i%26))))
		l.fromTUN(b, ip4(tunB, tunA, string(rune('A'+i%26))))
	}
	if len(a.tun) != 101 || len(b.tun) != 102 {
		t.Fatalf("a got %d packets, b got %d; want 101 and 102", len(a.tun), len(b.tun))
	}

	out := a.dev.HandleTUN(l.now, ip4(tunA, netip.MustParseAddr("10.0.0.99"), "nobody"))
	if len(out.Datagrams) != 0 || !hasDrop(out.Events, ReasonNoRoute) {
		t.Errorf("packet without a route: %d datagrams, events %v", len(out.Datagrams), out.Events)
	}
	out = a.dev.HandleTUN(l.now, []byte{0x45, 0, 0})
	if !hasDrop(out.Events, ReasonInvalid) {
		t.Errorf("truncated packet not dropped as invalid: %v", out.Events)
	}
}

func TestInboundAllowedIPsDrop(t *testing.T) {
	l, a, b := newPair(t, 11, nil)
	establish(t, l, a, b)
	mark := len(a.events)
	spoofed := ip4(netip.MustParseAddr("10.9.9.9"), tunA, "spoofed source")
	l.fromTUN(b, spoofed)
	if len(a.tun) != 0 {
		t.Fatalf("a accepted a packet whose source is outside b's allowed IPs")
	}
	if !hasDrop(a.events[mark:], ReasonAllowedIPs) {
		t.Fatalf("no %s drop: %v", ReasonAllowedIPs, a.events[mark:])
	}
	// The message itself was authentic, so the session goes on.
	l.fromTUN(b, ip4(tunB, tunA, "honest"))
	if len(a.tun) != 1 {
		t.Fatalf("honest packet after the spoofed one was not delivered")
	}
}

func TestCrossedInitiations(t *testing.T) {
	for seed := uint64(20); seed < 28; seed++ {
		l, a, b := newPair(t, seed, nil)
		l.absorb(a, a.dev.HandleTUN(0, ip4(tunA, tunB, "from a")))
		l.absorb(b, b.dev.HandleTUN(0, ip4(tunB, tunA, "from b")))
		l.runUntil(30 * sec)
		if len(a.tun) != 1 || len(b.tun) != 1 {
			t.Fatalf("seed %d: a got %d packets, b got %d; want 1 each", seed, len(a.tun), len(b.tun))
		}
		pa, pb := a.dev.peers[0], b.dev.peers[0]
		if pa.current == nil || pb.current == nil || !coherent(pa.current, pb.current) {
			t.Fatalf("seed %d: crossed initiations did not converge to one session", seed)
		}
		if pa.next != nil || pb.next != nil {
			t.Fatalf("seed %d: a keypair is still waiting in next", seed)
		}
	}
}

func TestCookieUnderLoad(t *testing.T) {
	l, a, b := newPair(t, 30, func(_, cb *Config) { cb.ForceUnderLoad = true })
	l.fromTUN(a, ip4(tunA, tunB, "under load"))
	if !hasDrop(b.events, ReasonCookie) {
		t.Fatalf("b under load accepted an initiation without mac2")
	}
	var cookies int
	for _, s := range b.sent {
		if noise.MessageType(s.Data) == noise.TypeCookieReply {
			cookies++
		}
	}
	if cookies != 1 || len(b.tun) != 0 {
		t.Fatalf("b sent %d cookie replies and received %d packets, want 1 and 0", cookies, len(b.tun))
	}
	var accepted int
	for _, e := range a.events {
		if e.Kind == EventCookie {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("a reported %d accepted cookie replies, want 1", accepted)
	}
	l.runUntil(6 * sec)
	if len(b.tun) != 1 {
		t.Fatalf("retried initiation with mac2 did not complete the handshake")
	}
}

func TestUnderLoadDetection(t *testing.T) {
	_, _, b := newPair(t, 31, nil)
	d := b.dev
	junk := make([]byte, noise.InitiationSize)
	junk[0] = noise.TypeInitiation
	var now int64
	for i := range UnderLoadHandshakes - 1 {
		now = int64(i) * 1e6
		d.HandleUDP(now, netip.MustParseAddrPort("192.0.2.9:1"), junk)
	}
	if d.underLoad(now) {
		t.Fatal("under load after 511 handshake messages")
	}
	now += 1e6
	d.HandleUDP(now, netip.MustParseAddrPort("192.0.2.9:1"), junk)
	if !d.underLoad(now) || !d.underLoad(now+UnderLoadWindow-1) {
		t.Fatal("not under load during the second after 512 handshake messages in one second")
	}
	if d.underLoad(now + UnderLoadWindow) {
		t.Fatal("still under load one second after the burst")
	}
}

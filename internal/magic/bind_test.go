package magic

import (
	"net/netip"
	"testing"
)

func transport() []byte {
	b := make([]byte, 32)
	b[0] = 4
	return b
}

func initiation() []byte {
	b := make([]byte, 148)
	b[0] = 1
	return b
}

func TestBindPaths(t *testing.T) {
	b := New()
	var k [32]byte
	k[0] = 9
	c1 := netip.MustParseAddrPort("192.0.2.1:51820")
	c2 := netip.MustParseAddrPort("[::ffff:198.51.100.7]:4000")
	pseudo := b.AddPeer(k, []netip.AddrPort{c1, c2, c1})
	if !IsPseudo(pseudo) || IsPseudo(c1) {
		t.Fatalf("pseudo endpoint %s", pseudo)
	}
	c2 = netip.AddrPortFrom(c2.Addr().Unmap(), c2.Port())

	// No relay, nothing heard: the first candidate, handshakes to all.
	if got := b.Route(0, pseudo, transport()); len(got) != 1 || got[0].Relay || got[0].Dst != c1 {
		t.Fatalf("no relay, transport: %+v", got)
	}
	if got := b.Route(0, pseudo, initiation()); len(got) != 2 || got[1].Dst != c2 {
		t.Fatalf("no relay, initiation: %+v", got)
	}

	// Relay up: the relay, a probe copy to the candidates at most once
	// per ProbeInterval for transport, always for handshakes.
	b.SetRelay(true)
	if p, _ := b.PathOf(0, k); p != PathRelay {
		t.Fatalf("path with relay = %s", p)
	}
	if got := b.Route(0, pseudo, transport()); len(got) != 3 || !got[0].Relay || got[0].RelayTo != k {
		t.Fatalf("relay, first transport: %+v", got)
	}
	if got := b.Route(ProbeInterval/2, pseudo, transport()); len(got) != 1 || !got[0].Relay {
		t.Fatalf("relay, transport within the probe interval: %+v", got)
	}
	if got := b.Route(ProbeInterval/2, pseudo, initiation()); len(got) != 3 {
		t.Fatalf("relay, initiation: %+v", got)
	}
	if got := b.Route(ProbeInterval, pseudo, transport()); len(got) != 3 {
		t.Fatalf("relay, transport after the probe interval: %+v", got)
	}

	// The relay delivers: the device sees the pseudo endpoint; nothing
	// that is not WireGuard, and nobody unknown, gets through.
	if src, ok := b.FromRelay(k, transport()); !ok || src != pseudo {
		t.Fatalf("FromRelay = %s %v", src, ok)
	}
	if _, ok := b.FromRelay(k, []byte("hello")); ok {
		t.Fatal("FromRelay accepted plain text")
	}
	if _, ok := b.FromRelay([32]byte{1}, transport()); ok {
		t.Fatal("FromRelay accepted an unknown node")
	}

	// A datagram from c2 confirms it: direct only, until DirectTimeout.
	now := int64(10e9)
	if src := b.FromUDP(now, c2, transport()); src != pseudo {
		t.Fatalf("FromUDP from a candidate = %s", src)
	}
	if p, ep := b.PathOf(now, k); p != PathDirect || ep != c2 {
		t.Fatalf("path after hearing c2 = %s %s", p, ep)
	}
	if got := b.Route(now+DirectTimeout-1, pseudo, transport()); len(got) != 1 || got[0].Relay || got[0].Dst != c2 {
		t.Fatalf("confirmed direct: %+v", got)
	}
	if got := b.Route(now+DirectTimeout, pseudo, transport()); !got[0].Relay || got[1].Dst != c2 {
		t.Fatalf("direct expired: %+v", got)
	}

	// An unknown address reaches the device as is; once the device roams
	// the peer there, it is the direct address.
	roam := netip.MustParseAddrPort("203.0.113.5:9999")
	if src := b.FromUDP(now, roam, transport()); src != roam {
		t.Fatalf("FromUDP from an unknown address = %s", src)
	}
	if back, ok := b.Roamed(now, k, roam); !ok || back != pseudo {
		t.Fatalf("Roamed = %s %v", back, ok)
	}
	if p, ep := b.PathOf(now, k); p != PathDirect || ep != roam {
		t.Fatalf("path after roaming = %s %s", p, ep)
	}
	if src := b.FromUDP(now, roam, transport()); src != pseudo {
		t.Fatalf("FromUDP from the roamed address = %s", src)
	}

	// New candidates keep the measured address; removal forgets it all.
	b.SetCandidates(k, nil)
	if src := b.FromUDP(now, c1, transport()); src != c1 {
		t.Fatalf("FromUDP from a dropped candidate = %s", src)
	}
	if src := b.FromUDP(now, roam, transport()); src != pseudo {
		t.Fatalf("FromUDP from the measured address after new candidates = %s", src)
	}
	b.RemovePeer(k)
	if b.Has(k) || b.FromUDP(now, roam, transport()) != roam {
		t.Fatal("peer still known after RemovePeer")
	}
	if got := b.Route(now, pseudo, transport()); got != nil {
		t.Fatalf("route to a removed peer's pseudo endpoint: %+v", got)
	}
	other := netip.MustParseAddrPort("192.0.2.9:1")
	if got := b.Route(now, other, transport()); len(got) != 1 || got[0].Dst != other {
		t.Fatalf("route to a real address: %+v", got)
	}
}

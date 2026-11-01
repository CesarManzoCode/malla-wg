package sim

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"
)

var (
	natPriv1 = netip.MustParseAddr("192.168.1.2")
	natPriv2 = netip.MustParseAddr("192.168.2.2")
	natExt   = netip.MustParseAddr("203.0.113.1")
	natCG    = netip.MustParseAddr("100.64.0.2")
	natCG2   = netip.MustParseAddr("100.64.0.3")
	natSrv1  = netip.MustParseAddr("198.51.100.10")
	natSrv2  = netip.MustParseAddr("198.51.100.20")
)

// inbox records the sources of the datagrams delivered to a port.
type inbox struct{ from []netip.AddrPort }

func listen(h *Host, port uint16) *inbox {
	b := &inbox{}
	h.Listen(port, func(src, _ netip.AddrPort, _ []byte) { b.from = append(b.from, src) })
	return b
}

// last returns the source of the last datagram delivered, failing if none.
func (b *inbox) last(t *testing.T) netip.AddrPort {
	t.Helper()
	if len(b.from) == 0 {
		t.Fatal("no datagram delivered")
	}
	return b.from[len(b.from)-1]
}

// linkAll connects every pair of hosts with a 1 ms link: the links are the
// paths, and the NATs rewrite the datagrams that cross them.
func linkAll(s *Sim, hosts ...*Host) {
	for i := range hosts {
		for j := i + 1; j < len(hosts); j++ {
			s.Connect(hosts[i], hosts[j], LinkConfig{Latency: Ms})
		}
	}
}

// settle runs the simulation 10 ms forward, enough to deliver everything
// sent so far.
func settle(t *testing.T, s *Sim) {
	t.Helper()
	if err := s.RunUntil(s.Now() + 10*Ms); err != nil {
		t.Fatal(err)
	}
}

// countLog counts the log records of type ev and, if reason is not empty,
// with that reason.
func countLog(t *testing.T, log []byte, ev, reason string) int {
	t.Helper()
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(log))
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("log line %q: %v", sc.Text(), err)
		}
		if r.Ev == ev && (reason == "" || r.Reason == reason) {
			n++
		}
	}
	return n
}

// TestNATMapping checks the external port each mapping behavior gives to
// one internal endpoint toward three destinations: two ports of one server
// and another server. otherPort and otherAddr say whether the port changes
// for another port of the same server and for another server.
func TestNATMapping(t *testing.T) {
	for _, tc := range []struct {
		m                    Mapping
		otherPort, otherAddr bool
	}{
		{EIM, false, false},
		{ADM, false, true},
		{APDM, true, true},
	} {
		t.Run(tc.m.String(), func(t *testing.T) {
			var log bytes.Buffer
			s := New(1, &log)
			a := s.NewHost("a", natPriv1)
			s1, s2 := s.NewHost("s1", natSrv1), s.NewHost("s2", natSrv2)
			linkAll(s, a, s1, s2)
			s.NewNAT("nat", natExt, NATConfig{Mapping: tc.m}).Add(a)
			in1, in1b, in2 := listen(s1, 7000), listen(s1, 7001), listen(s2, 7000)
			a.Send(5000, s1.AddrPort(7000), []byte("x"))
			a.Send(5000, s1.AddrPort(7001), []byte("x"))
			a.Send(5000, s2.AddrPort(7000), []byte("x"))
			a.Send(5000, s1.AddrPort(7000), []byte("x"))
			settle(t, s)
			base := in1.from[0]
			if base.Addr() != natExt {
				t.Fatalf("server saw %v, want the NAT's external address", base)
			}
			if in1.last(t) != base {
				t.Errorf("same destination again: port %d, first was %d", in1.last(t).Port(), base.Port())
			}
			if got := in1b.last(t) != base; got != tc.otherPort {
				t.Errorf("other port of the server: %v, first %v (want change=%v)", in1b.last(t), base, tc.otherPort)
			}
			if got := in2.last(t) != base; got != tc.otherAddr {
				t.Errorf("other server: %v, first %v (want change=%v)", in2.last(t), base, tc.otherAddr)
			}
			mappings := 1
			if tc.otherPort {
				mappings++
			}
			if tc.otherAddr {
				mappings++
			}
			if got := countLog(t, log.Bytes(), "nat_map", ""); got != mappings {
				t.Errorf("%d nat_map events, want %d", got, mappings)
			}
		})
	}
}

// TestNATFiltering checks what each filtering behavior lets through to a
// mapping opened toward s1:7000 (RFC 4787 §5): the same endpoint always,
// another port of s1 with EIF and ADF, another server only with EIF. A
// port without a mapping is dropped as no_mapping.
func TestNATFiltering(t *testing.T) {
	for _, tc := range []struct {
		f    Filtering
		pass [3]bool // same endpoint, same address, other address
	}{
		{EIF, [3]bool{true, true, true}},
		{ADF, [3]bool{true, true, false}},
		{APDF, [3]bool{true, false, false}},
	} {
		t.Run(tc.f.String(), func(t *testing.T) {
			var log bytes.Buffer
			s := New(1, &log)
			a := s.NewHost("a", natPriv1)
			s1, s2 := s.NewHost("s1", natSrv1), s.NewHost("s2", natSrv2)
			linkAll(s, a, s1, s2)
			s.NewNAT("nat", natExt, NATConfig{Filtering: tc.f}).Add(a)
			inA, in1 := listen(a, 5000), listen(s1, 7000)
			a.Send(5000, s1.AddrPort(7000), []byte("x"))
			settle(t, s)
			ext := in1.last(t)
			drops := 0
			for _, probe := range []struct {
				name string
				from *Host
				port uint16
				pass bool
			}{
				{"same endpoint", s1, 7000, tc.pass[0]},
				{"same address, other port", s1, 7001, tc.pass[1]},
				{"other address", s2, 7000, tc.pass[2]},
			} {
				before := len(inA.from)
				probe.from.Send(probe.port, ext, []byte("y"))
				settle(t, s)
				got := len(inA.from) > before
				if got != probe.pass {
					t.Errorf("%s: delivered=%v, want %v", probe.name, got, probe.pass)
				}
				if got && inA.last(t) != probe.from.AddrPort(probe.port) {
					t.Errorf("%s: a saw source %v, want %v", probe.name, inA.last(t), probe.from.AddrPort(probe.port))
				}
				if !probe.pass {
					drops++
				}
			}
			if got := countLog(t, log.Bytes(), "drop", DropNATFilter); got != drops {
				t.Errorf("%d nat_filter drops, want %d", got, drops)
			}
			s2.Send(7000, netip.AddrPortFrom(natExt, ext.Port()+1), []byte("z"))
			settle(t, s)
			if got := countLog(t, log.Bytes(), "drop", DropNoMapping); got != 1 {
				t.Errorf("%d no_mapping drops for an unmapped port, want 1", got)
			}
		})
	}
}

// TestNATHairpin puts two hosts behind one EIM-APDF NAT. With hairpin a
// datagram to the other's external endpoint arrives with the sender's
// external endpoint as source, after the filter of the receiving mapping
// lets it in; without hairpin it is not routed.
func TestNATHairpin(t *testing.T) {
	for _, hairpin := range []bool{true, false} {
		var log bytes.Buffer
		s := New(1, &log)
		a, b := s.NewHost("a", natPriv1), s.NewHost("b", natPriv2)
		srv := s.NewHost("s", natSrv1)
		linkAll(s, a, b, srv)
		s.NewNAT("nat", natExt, NATConfig{Mapping: EIM, Filtering: APDF, Hairpin: hairpin}).Add(a, b)
		inA, inB, inS := listen(a, 5000), listen(b, 5000), listen(srv, 7000)
		a.Send(5000, srv.AddrPort(7000), []byte("x"))
		settle(t, s)
		extA := inS.last(t)
		b.Send(5000, srv.AddrPort(7000), []byte("x"))
		settle(t, s)
		extB := inS.last(t)
		a.Send(5000, extB, []byte("punch")) // opens a's filter to extB
		settle(t, s)
		b.Send(5000, extA, []byte("punch"))
		settle(t, s)
		a.Send(5000, extB, []byte("data"))
		settle(t, s)
		if !hairpin {
			if len(inA.from)+len(inB.from) != 0 {
				t.Errorf("no hairpin: a got %d and b got %d datagrams, want none", len(inA.from), len(inB.from))
			}
			if got := countLog(t, log.Bytes(), "drop", DropNoRoute); got != 3 {
				t.Errorf("no hairpin: %d no_route drops, want 3", got)
			}
			continue
		}
		if got := countLog(t, log.Bytes(), "drop", DropNATFilter); got != 1 {
			t.Errorf("hairpin: %d nat_filter drops, want 1 (the first punch)", got)
		}
		if len(inA.from) != 1 || inA.from[0] != extB {
			t.Errorf("hairpin: a saw %v, want [%v]", inA.from, extB)
		}
		if len(inB.from) != 1 || inB.from[0] != extA {
			t.Errorf("hairpin: b saw %v, want [%v]", inB.from, extA)
		}
	}
}

// TestNATCGNAT nests a home NAT inside a carrier-grade NAT: the server sees
// the CGNAT's address, its reply reaches the host, and an unsolicited
// datagram from another server is dropped by the more restrictive filter,
// whichever of the two NATs has it.
func TestNATCGNAT(t *testing.T) {
	for _, tc := range []struct {
		name      string
		home, cgn Filtering
	}{
		{"home EIF, CGNAT APDF", EIF, APDF},
		{"home APDF, CGNAT EIF", APDF, EIF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var log bytes.Buffer
			s := New(1, &log)
			a := s.NewHost("a", natPriv1)
			s1, s2 := s.NewHost("s1", natSrv1), s.NewHost("s2", natSrv2)
			linkAll(s, a, s1, s2)
			cg := s.NewNAT("cgnat", natExt, NATConfig{Filtering: tc.cgn})
			cg.NewNAT("home", natCG, NATConfig{Filtering: tc.home}).Add(a)
			inA, in1 := listen(a, 5000), listen(s1, 7000)
			a.Send(5000, s1.AddrPort(7000), []byte("x"))
			settle(t, s)
			ext := in1.last(t)
			if ext.Addr() != natExt {
				t.Fatalf("server saw %v, want the CGNAT's address", ext)
			}
			if got := countLog(t, log.Bytes(), "nat_map", ""); got != 2 {
				t.Errorf("%d nat_map events, want 2 (home and CGNAT)", got)
			}
			s1.Send(7000, ext, []byte("reply"))
			settle(t, s)
			if len(inA.from) != 1 || inA.from[0] != s1.AddrPort(7000) {
				t.Fatalf("a saw %v, want the reply from %v", inA.from, s1.AddrPort(7000))
			}
			s2.Send(7000, ext, []byte("unsolicited"))
			settle(t, s)
			if len(inA.from) != 1 {
				t.Errorf("the unsolicited datagram reached a")
			}
			if got := countLog(t, log.Bytes(), "drop", DropNATFilter); got != 1 {
				t.Errorf("%d nat_filter drops, want 1", got)
			}
		})
	}
}

// TestNATCGNATHairpin puts two hosts, each behind its own EIM-EIF home NAT,
// behind one CGNAT with hairpin: each reaches the other through the
// CGNAT's external address and sees the other's external endpoint.
func TestNATCGNATHairpin(t *testing.T) {
	s := New(1, nil)
	a, b := s.NewHost("a", natPriv1), s.NewHost("b", natPriv2)
	srv := s.NewHost("s", natSrv1)
	linkAll(s, a, b, srv)
	cg := s.NewNAT("cgnat", natExt, NATConfig{Hairpin: true})
	cg.NewNAT("home-a", natCG, NATConfig{}).Add(a)
	cg.NewNAT("home-b", natCG2, NATConfig{}).Add(b)
	inA, inB, inS := listen(a, 5000), listen(b, 5000), listen(srv, 7000)
	a.Send(5000, srv.AddrPort(7000), []byte("x"))
	settle(t, s)
	extA := inS.last(t)
	b.Send(5000, srv.AddrPort(7000), []byte("x"))
	settle(t, s)
	extB := inS.last(t)
	a.Send(5000, extB, []byte("ab"))
	b.Send(5000, extA, []byte("ba"))
	settle(t, s)
	if len(inB.from) != 1 || inB.from[0] != extA {
		t.Errorf("b saw %v, want [%v]", inB.from, extA)
	}
	if len(inA.from) != 1 || inA.from[0] != extB {
		t.Errorf("a saw %v, want [%v]", inA.from, extB)
	}
}

// TestNATExpire checks the idle timeout: a mapping refreshed at 100 s by
// an outbound datagram and at 200 s by an inbound one lives until 320 s,
// then expires with a nat_expire event, an inbound datagram finds no
// mapping, and the next outbound one gets a new port.
func TestNATExpire(t *testing.T) {
	var log bytes.Buffer
	s := New(1, &log)
	a, srv := s.NewHost("a", natPriv1), s.NewHost("s", natSrv1)
	linkAll(s, a, srv)
	s.NewNAT("nat", natExt, NATConfig{}).Add(a)
	inA, inS := listen(a, 5000), listen(srv, 7000)
	a.Send(5000, srv.AddrPort(7000), []byte("x"))
	settle(t, s)
	ext := inS.last(t)
	at := func(sec int64, fn func()) {
		s.At(sec*1e9, fn)
		if err := s.RunUntil(sec*1e9 + 10*Ms); err != nil {
			t.Fatal(err)
		}
	}
	at(100, func() { a.Send(5000, srv.AddrPort(7000), []byte("keep")) })
	at(200, func() { srv.Send(7000, ext, []byte("alive")) })
	if len(inA.from) != 1 {
		t.Fatalf("at 200 s the reply did not arrive: a got %d datagrams", len(inA.from))
	}
	if got := countLog(t, log.Bytes(), "nat_expire", ""); got != 0 {
		t.Fatalf("%d nat_expire events before the timeout", got)
	}
	// The reply at 200 s refreshed the mapping too, so it lives until 320 s.
	at(319, func() {})
	if got := countLog(t, log.Bytes(), "nat_expire", ""); got != 0 {
		t.Fatalf("%d nat_expire events at 319 s, want 0", got)
	}
	at(321, func() { srv.Send(7000, ext, []byte("late")) })
	if got := countLog(t, log.Bytes(), "nat_expire", ""); got != 1 {
		t.Errorf("%d nat_expire events at 321 s, want 1", got)
	}
	if got := countLog(t, log.Bytes(), "drop", DropNoMapping); got != 1 {
		t.Errorf("%d no_mapping drops after the expiry, want 1", got)
	}
	at(322, func() { a.Send(5000, srv.AddrPort(7000), []byte("again")) })
	if again := inS.last(t); again == ext {
		t.Errorf("after the expiry the host got the same mapping %v again", again)
	}
	if got := countLog(t, log.Bytes(), "nat_map", ""); got != 2 {
		t.Errorf("%d nat_map events, want 2", got)
	}
}

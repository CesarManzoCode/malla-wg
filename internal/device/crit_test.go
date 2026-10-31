package device

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/CesarManzoCode/malla-wg/internal/noise"
)

// TestCritRekeyTimers is criterion 10 (contract §7) on two devices joined
// by a fake link under a virtual clock: the timers of the contract §6.
func TestCritRekeyTimers(t *testing.T) {
	violated := func(t *testing.T, format string, args ...any) {
		t.Helper()
		t.Fatalf("property rekey violated: "+format, args...)
	}

	t.Run("send-side rekey only for the initiator after 120 s", func(t *testing.T) {
		l, a, b := newPair(t, 1, nil)
		establish(t, l, a, b)
		l.runUntil(119 * sec)
		markA, markB := len(a.sent), len(b.sent)
		l.fromTUN(a, ip4(tunA, tunB, "at 119 s"))
		if ts := initiationTimes(a, markA); len(ts) != 0 {
			violated(t, "initiator sent an initiation at %v with a key of 119 s", ts)
		}
		l.runUntil(121 * sec)
		l.fromTUN(b, ip4(tunB, tunA, "responder at 121 s"))
		if ts := initiationTimes(b, markB); len(ts) != 0 {
			violated(t, "responder sent an initiation at %v when sending with a key of 121 s", ts)
		}
		if ts := initiationTimes(a, markA); len(ts) != 0 {
			violated(t, "initiator sent an initiation at %v when receiving with a key of 121 s", ts)
		}
		l.runUntil(125 * sec)
		l.fromTUN(a, ip4(tunA, tunB, "initiator at 125 s"))
		if ts := initiationTimes(a, markA); len(ts) != 1 || ts[0] != 125*sec {
			violated(t, "initiator sending with a key of 125 s sent initiations at %v, want one at 125 s", ts)
		}
		l.runUntil(126 * sec)
		pa, pb := a.dev.peers[0], b.dev.peers[0]
		if pa.current == nil || pa.current.birth != 125*sec || pb.current == nil || !coherent(pa.current, pb.current) {
			violated(t, "the rekey at 125 s did not leave one coherent new session")
		}
		if ts := initiationTimes(b, markB); len(ts) != 0 {
			violated(t, "responder sent initiations at %v", ts)
		}
	})

	t.Run("receive-side rekey at 165 s", func(t *testing.T) {
		l, a, b := newPair(t, 2, nil)
		establish(t, l, a, b)
		markA := len(a.sent)
		l.runUntil(100 * sec)
		l.fromTUN(b, ip4(tunB, tunA, "at 100 s"))
		l.runUntil(164 * sec)
		l.fromTUN(b, ip4(tunB, tunA, "at 164 s"))
		if ts := initiationTimes(a, markA); len(ts) != 0 {
			violated(t, "initiator sent initiations at %v before its key was 165 s old", ts)
		}
		l.runUntil(166 * sec)
		l.fromTUN(b, ip4(tunB, tunA, "at 166 s"))
		if ts := initiationTimes(a, markA); len(ts) != 1 || ts[0] != 166*sec {
			violated(t, "initiator receiving with a key of 166 s sent initiations at %v, want one at 166 s", ts)
		}
	})

	t.Run("reject a key older than 180 s", func(t *testing.T) {
		l, a, b := newPair(t, 3, nil)
		establish(t, l, a, b)
		l.runUntil(50 * sec)
		l.drop = func(*node, Datagram) bool { return true }
		markB := len(b.sent)
		l.fromTUN(b, ip4(tunB, tunA, "first"))
		l.fromTUN(b, ip4(tunB, tunA, "second"))
		var captured [][]byte
		for _, s := range b.sent[markB:] {
			if noise.MessageType(s.Data) == noise.TypeTransport {
				captured = append(captured, s.Data)
			}
		}
		if len(captured) != 2 {
			t.Fatalf("captured %d data messages, want 2", len(captured))
		}
		l.runUntil(179 * sec)
		out := a.dev.HandleUDP(l.now, b.addr, captured[0])
		if len(out.Packets) != 1 {
			violated(t, "a packet under a key of 179 s was not accepted (events %v)", out.Events)
		}
		l.runUntil(181 * sec)
		out = a.dev.HandleUDP(l.now, b.addr, captured[1])
		if len(out.Packets) != 0 || !hasDrop(out.Events, ReasonExpired) {
			violated(t, "a packet under a key of 181 s was not rejected as expired (packets %d, events %v)", len(out.Packets), out.Events)
		}
		l.runUntil(185 * sec)
		out = a.dev.HandleTUN(l.now, ip4(tunA, tunB, "late"))
		for _, d := range out.Datagrams {
			if noise.MessageType(d.Data) == noise.TypeTransport {
				violated(t, "a data message was sent with a key of 185 s")
			}
		}
	})

	t.Run("initiation retries every 5 s plus jitter until 90 s", func(t *testing.T) {
		l, a, _ := newPair(t, 4, nil)
		l.drop = func(from *node, _ Datagram) bool { return from == a }
		l.fromTUN(a, ip4(tunA, tunB, "nobody answers"))
		l.runUntil(200 * sec)
		ts := initiationTimes(a, 0)
		if len(ts) == 0 || ts[0] != 0 {
			violated(t, "first initiation at %v, want at 0", ts)
		}
		for i := 1; i < len(ts); i++ {
			if gap := ts[i] - ts[i-1]; gap < RekeyTimeout || gap > RekeyTimeout+333e6 {
				violated(t, "retry %d came %d ns after the previous one, want within [5 s, 5.333 s]", i, gap)
			}
		}
		last := ts[len(ts)-1]
		if last >= RekeyAttemptTime {
			violated(t, "an initiation was sent at %d ns, at or after 90 s", last)
		}
		if last+RekeyTimeout+333e6 < RekeyAttemptTime {
			violated(t, "retries stopped at %d ns, before 90 s", last)
		}
		for _, s := range a.sent {
			if s.at >= RekeyAttemptTime {
				violated(t, "a datagram was sent at %d ns after giving up", s.at)
			}
		}
		if !hasDrop(a.events, ReasonHandshakeTimeout) {
			violated(t, "no %s drop after giving up", ReasonHandshakeTimeout)
		}
	})

	t.Run("keepalive 10 s after received data", func(t *testing.T) {
		l, a, b := newPair(t, 5, nil)
		establish(t, l, a, b)
		l.runUntil(30 * sec)
		l.fromTUN(b, ip4(tunB, tunA, "needs an answer"))
		if got := a.dev.NextDeadline(); got != 40*sec {
			violated(t, "next deadline after receiving data at 30 s is %d, want 40 s", got)
		}
		mark := len(a.sent)
		l.runUntil(40*sec - 1)
		if len(a.sent) != mark {
			violated(t, "sent %d datagrams before the keepalive was due", len(a.sent)-mark)
		}
		l.runUntil(40 * sec)
		sent := a.sent[mark:]
		if len(sent) != 1 || sent[0].at != 40*sec || len(sent[0].Data) != noise.TransportMinSize {
			violated(t, "want one %d-byte keepalive at 40 s, got %d datagrams", noise.TransportMinSize, len(sent))
		}
	})
}

// TestCritRoaming is criterion 12: only an authenticated message moves the
// endpoint (D07).
func TestCritRoaming(t *testing.T) {
	violated := func(format string, args ...any) {
		t.Helper()
		t.Fatalf("property roaming violated: "+format, args...)
	}
	l, a, b := newPair(t, 6, nil)
	establish(t, l, a, b)
	pubB := b.dev.PublicKey()

	// b moves to a new address and sends valid data from there.
	moved := netip.MustParseAddrPort("203.0.113.9:40000")
	b.addr = moved
	l.runUntil(1 * sec)
	l.fromTUN(b, ip4(tunB, tunA, "from the new address"))
	if ep, _ := a.dev.Endpoint(pubB); ep != moved {
		violated("endpoint is %v after valid data from %v", ep, moved)
	}
	markA, markB := len(a.sent), len(b.tun)
	l.fromTUN(a, ip4(tunA, tunB, "reply"))
	if len(a.sent) == markA || a.sent[len(a.sent)-1].Dst != moved {
		violated("reply did not go to the new address")
	}
	if len(b.tun) != markB+1 {
		violated("b did not receive the reply at the new address")
	}

	// Unauthenticated datagrams from another address do not move it.
	attacker := netip.MustParseAddrPort("192.0.2.66:6666")
	valid := b.dev.HandleTUN(l.now, ip4(tunB, tunA, "captured")).Datagrams
	if len(valid) != 1 || noise.MessageType(valid[0].Data) != noise.TypeTransport {
		t.Fatal("could not produce a data message from b")
	}
	tampered := bytes.Clone(valid[0].Data)
	tampered[len(tampered)-1] ^= 1
	garbageData := bytes.Clone(valid[0].Data)
	for i := noise.TransportHeaderSize; i < len(garbageData); i++ {
		garbageData[i] = byte(i * 7)
	}
	garbageInit := make([]byte, noise.InitiationSize)
	garbageInit[0] = noise.TypeInitiation
	for i := 4; i < len(garbageInit); i++ {
		garbageInit[i] = byte(i)
	}
	for _, c := range []struct {
		name string
		data []byte
		why  string
	}{
		{"tampered tag", tampered, ReasonDecrypt},
		{"garbage data", garbageData, ReasonDecrypt},
		{"garbage initiation", garbageInit, ReasonMAC1},
		{"random bytes", []byte("not wireguard at all"), ReasonType},
	} {
		out := a.dev.HandleUDP(l.now, attacker, c.data)
		if ep, _ := a.dev.Endpoint(pubB); ep != moved {
			violated("%s from %v moved the endpoint to %v", c.name, attacker, ep)
		}
		if len(out.Packets) != 0 || !hasDrop(out.Events, c.why) {
			violated("%s was not dropped as %s (events %v)", c.name, c.why, out.Events)
		}
	}

	// The genuine message moves it; its replay from elsewhere does not.
	if out := a.dev.HandleUDP(l.now, attacker, valid[0].Data); len(out.Packets) != 1 {
		violated("valid data from %v was not accepted", attacker)
	}
	if ep, _ := a.dev.Endpoint(pubB); ep != attacker {
		violated("valid data from %v left the endpoint at %v", attacker, ep)
	}
	other := netip.MustParseAddrPort("192.0.2.77:7777")
	out := a.dev.HandleUDP(l.now, other, valid[0].Data)
	if ep, _ := a.dev.Endpoint(pubB); ep != attacker || !hasDrop(out.Events, ReasonReplay) {
		violated("a replayed message from %v moved the endpoint to %v", other, ep)
	}
}

package sim

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/CesarManzoCode/malla-wg/internal/device"
	"github.com/CesarManzoCode/malla-wg/internal/noise"
)

const testWall int64 = 1_793_000_000 * 1e9

// pairScenario runs two devices that send each other a packet every 100 ms
// for 10 s over a link with loss and jitter, and returns the event log and
// how many packets each TUN received.
func pairScenario(t *testing.T, seed uint64) (log []byte, gotA, gotB int) {
	t.Helper()
	var buf bytes.Buffer
	s := New(seed, &buf)
	ha := s.NewHost("a", netip.MustParseAddr("192.0.2.1"))
	hb := s.NewHost("b", netip.MustParseAddr("198.51.100.2"))
	s.Connect(ha, hb, LinkConfig{Latency: 20 * Ms, Jitter: 15 * Ms, Loss: 0.1})
	privA, err := noise.GeneratePrivateKey(ha.Rand)
	if err != nil {
		t.Fatal(err)
	}
	privB, err := noise.GeneratePrivateKey(hb.Rand)
	if err != nil {
		t.Fatal(err)
	}
	tunA, tunB := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	const port = 51820
	peer := func(priv [noise.KeySize]byte, inner netip.Addr, h *Host) device.PeerConfig {
		return device.PeerConfig{
			PublicKey:  noise.NewLocal(priv).PublicKey(),
			AllowedIPs: []netip.Prefix{netip.PrefixFrom(inner, 32)},
			Endpoint:   h.AddrPort(port),
		}
	}
	a, err := AttachDevice(ha, port, device.Config{PrivateKey: privA, WallOffset: testWall,
		Peers: []device.PeerConfig{peer(privB, tunB, hb)}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := AttachDevice(hb, port, device.Config{PrivateKey: privB, WallOffset: testWall + 3e9,
		Peers: []device.PeerConfig{peer(privA, tunA, ha)}})
	if err != nil {
		t.Fatal(err)
	}
	for i := range int64(100) {
		var payload [8]byte
		binary.BigEndian.PutUint64(payload[:], uint64(i))
		s.At(i*100*Ms, func() { a.Inject(IPv4Packet(tunA, tunB, payload[:])) })
		s.At(i*100*Ms+7*Ms, func() { b.Inject(IPv4Packet(tunB, tunA, payload[:])) })
	}
	if err := s.RunUntil(15e9); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), len(a.TUN), len(b.TUN)
}

// TestCritDeterminism is criterion 25: the same seed gives the same event
// log byte for byte, and another seed a different one.
func TestCritDeterminism(t *testing.T) {
	first, gotA, gotB := pairScenario(t, 7)
	second, _, _ := pairScenario(t, 7)
	other, _, _ := pairScenario(t, 8)
	if gotA == 0 || gotB == 0 {
		t.Fatalf("scenario exchanged no data: a got %d packets, b got %d", gotA, gotB)
	}
	for _, want := range []string{`"ev":"drop"`, `"reason":"loss"`, `"ev":"handshake"`, `"ev":"tun"`} {
		if !bytes.Contains(first, []byte(want)) {
			t.Errorf("log of seed 7 has no %s", want)
		}
	}
	if !bytes.Equal(first, second) {
		i := 0
		for i < min(len(first), len(second)) && first[i] == second[i] {
			i++
		}
		t.Fatalf("seed 7 gave two different logs (%d and %d bytes), first difference at byte %d", len(first), len(second), i)
	}
	if bytes.Equal(first, other) {
		t.Fatal("seeds 7 and 8 gave the same log")
	}
}

// TestLogFieldOrder checks the field order of the contract §5.
func TestLogFieldOrder(t *testing.T) {
	var buf bytes.Buffer
	s := New(1, &buf)
	s.At(5, func() { s.Log(Record{Ev: "path", Node: "a", Reason: "direct"}) })
	if err := s.RunUntil(10); err != nil {
		t.Fatal(err)
	}
	want := `{"t":5,"seq":1,"ev":"path","node":"a","reason":"direct"}` + "\n"
	if buf.String() != want {
		t.Fatalf("log line = %q, want %q", buf.String(), want)
	}
}

// TestSchedulerOrder checks that events run by (time, sequence).
func TestSchedulerOrder(t *testing.T) {
	s := New(1, nil)
	var got []int
	s.At(20, func() { got = append(got, 3) })
	s.At(10, func() { got = append(got, 1) })
	s.At(10, func() {
		got = append(got, 2)
		s.At(0, func() { got = append(got, 21) }) // past: runs now, after queued peers
	})
	s.At(20, func() { got = append(got, 4) })
	if err := s.RunUntil(20); err != nil {
		t.Fatal(err)
	}
	want := []int{1, 2, 21, 3, 4}
	if len(got) != len(want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
	if s.Now() != 20 {
		t.Fatalf("Now = %d, want 20", s.Now())
	}
}

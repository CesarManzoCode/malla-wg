package sim

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/device"
	"github.com/CesarManzoCode/malla-wg/internal/noise"
)

// mappingScenario is the short mapping timeout scenario of the contract
// §6: device a behind an EIM-APDF NAT whose mappings expire after 30 s
// idle, device b public and knowing a only by roaming. a sends "hello" at
// 0 s and b answers "reply" at 1 s; then nothing crosses on purpose until
// b sends "late" at 60 s, a sends "again" at 65 s and b sends "after" at
// 66 s. keepalive is a's persistent keepalive toward b, 0 for none.
func mappingScenario(t *testing.T, seed uint64, keepalive time.Duration) (log []byte, a, b *DeviceNode, pubA [noise.KeySize]byte) {
	t.Helper()
	var buf bytes.Buffer
	s := New(seed, &buf)
	ha := s.NewHost("a", natPriv1)
	hb := s.NewHost("b", natSrv1)
	s.NewNAT("nat", natExt, NATConfig{Mapping: EIM, Filtering: APDF, Timeout: 30e9}).Add(ha)
	s.Connect(ha, hb, LinkConfig{Latency: 20 * Ms, Jitter: 5 * Ms})
	privA, err := noise.GeneratePrivateKey(ha.Rand)
	if err != nil {
		t.Fatal(err)
	}
	privB, err := noise.GeneratePrivateKey(hb.Rand)
	if err != nil {
		t.Fatal(err)
	}
	pubA, pubB := noise.NewLocal(privA).PublicKey(), noise.NewLocal(privB).PublicKey()
	tunA, tunB := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	const port = 51820
	a, err = AttachDevice(ha, port, device.Config{PrivateKey: privA, WallOffset: testWall,
		Peers: []device.PeerConfig{{PublicKey: pubB, AllowedIPs: []netip.Prefix{netip.PrefixFrom(tunB, 32)},
			Endpoint: hb.AddrPort(port), PersistentKeepalive: keepalive}}})
	if err != nil {
		t.Fatal(err)
	}
	b, err = AttachDevice(hb, port, device.Config{PrivateKey: privB, WallOffset: testWall + 3e9,
		Peers: []device.PeerConfig{{PublicKey: pubA, AllowedIPs: []netip.Prefix{netip.PrefixFrom(tunA, 32)}}}})
	if err != nil {
		t.Fatal(err)
	}
	send := func(at int64, n *DeviceNode, src, dst netip.Addr, msg string) {
		s.At(at, func() { n.Inject(IPv4Packet(src, dst, []byte(msg))) })
	}
	send(0, a, tunA, tunB, "hello")
	send(1e9, b, tunB, tunA, "reply")
	send(60e9, b, tunB, tunA, "late")
	send(65e9, a, tunA, tunB, "again")
	send(66e9, b, tunB, tunA, "after")
	if err := s.RunUntil(70e9); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), a, b, pubA
}

// received reports whether n wrote to its TUN the packet carrying msg.
func received(n *DeviceNode, msg string) bool {
	for _, p := range n.TUN {
		if len(p) >= 20 && string(p[20:]) == msg {
			return true
		}
	}
	return false
}

// TestMappingTimeoutKeepalive: with a 30 s mapping timeout, a's persistent
// keepalive of 25 s keeps the mapping, so the direct path stays: b's
// "late" packet, after 59 s without data, reaches a through the same
// external endpoint, and no mapping expires.
func TestMappingTimeoutKeepalive(t *testing.T) {
	seed := Seed(1)
	log, a, b, pubA := mappingScenario(t, seed, 25*time.Second)
	if n := countLog(t, log, "nat_expire", ""); n != 0 {
		Fatal(t, seed, "%d mappings expired with a persistent keepalive of 25 s", n)
	}
	for _, msg := range []string{"reply", "late", "after"} {
		if !received(a, msg) {
			Fatal(t, seed, "a did not receive %q", msg)
		}
	}
	if !received(b, "hello") || !received(b, "again") {
		Fatal(t, seed, "b did not receive both of a's packets")
	}
	if ep, _ := b.Dev.Endpoint(pubA); ep != netip.AddrPortFrom(natExt, 1024) {
		Fatal(t, seed, "b's endpoint for a is %v, want the first mapping %v:1024", ep, natExt)
	}
}

// TestMappingTimeoutNoKeepalive: without keepalive the mapping expires
// while the path is idle, b's "late" packet finds no mapping, and traffic
// recovers once a sends again: a new mapping, to which b roams, carries
// b's "after".
func TestMappingTimeoutNoKeepalive(t *testing.T) {
	seed := Seed(1)
	log, a, b, pubA := mappingScenario(t, seed, 0)
	if countLog(t, log, "nat_expire", "") == 0 {
		Fatal(t, seed, "no mapping expired after 49 s idle with a 30 s timeout")
	}
	if countLog(t, log, "drop", DropNoMapping) == 0 || received(a, "late") {
		Fatal(t, seed, "b's packet after the expiry was not dropped for lack of a mapping")
	}
	if !received(b, "again") || !received(a, "after") {
		Fatal(t, seed, "traffic did not recover: b got a's packet %v, a got b's answer %v",
			received(b, "again"), received(a, "after"))
	}
	if ep, _ := b.Dev.Endpoint(pubA); ep != netip.AddrPortFrom(natExt, 1025) {
		Fatal(t, seed, "b's endpoint for a is %v, want the new mapping %v:1025", ep, natExt)
	}
}

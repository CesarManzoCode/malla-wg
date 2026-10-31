package runtime

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/device"
	"github.com/CesarManzoCode/malla-wg/internal/tun"
	"github.com/CesarManzoCode/malla-wg/internal/x25519"
)

func genKey(t *testing.T) (priv, pub [32]byte) {
	t.Helper()
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	return priv, x25519.PublicKey(priv)
}

func listen(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// ipv4 builds a minimal IPv4 packet from src to dst with protocol UDP.
func ipv4(src, dst string, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8], b[9] = 64, 17
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	copy(b[20:], payload)
	return b
}

func expectPacket(t *testing.T, m *tun.Mem, want []byte) {
	t.Helper()
	select {
	case got := <-m.Outbound():
		if !bytes.Equal(got, want) {
			t.Fatalf("%s got packet %x, want %x", m.Name(), got, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: no packet within 10 s", m.Name())
	}
}

// TestMemTUNExchange runs two real nodes over UDP on 127.0.0.1 with
// in-memory TUNs: a packet injected into one comes out of the other after a
// real handshake, and the reply comes back over the same session.
func TestMemTUNExchange(t *testing.T) {
	privA, pubA := genKey(t)
	privB, pubB := genKey(t)
	connA, connB := listen(t), listen(t)
	addrA := connA.LocalAddr().(*net.UDPAddr).AddrPort()
	addrB := connB.LocalAddr().(*net.UDPAddr).AddrPort()
	tunA, tunB := tun.NewMem("memA", 16), tun.NewMem("memB", 16)

	nodeA, err := New(Config{Conn: connA, TUN: tunA, Device: device.Config{
		PrivateKey: privA,
		Peers: []device.PeerConfig{{PublicKey: pubB, Endpoint: addrB,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.200.0.2/32")}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	// B starts without A's endpoint: it learns it from the handshake.
	nodeB, err := New(Config{Conn: connB, TUN: tunB, Device: device.Config{
		PrivateKey: privB,
		Peers: []device.PeerConfig{{PublicKey: pubA,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.200.0.1/32")}}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 2)
	go func() { errs <- nodeA.Run(ctx) }()
	go func() { errs <- nodeB.Run(ctx) }()
	defer func() {
		cancel()
		for range 2 {
			if err := <-errs; err != nil {
				t.Errorf("Run: %v", err)
			}
		}
	}()

	ping := ipv4("10.200.0.1", "10.200.0.2", []byte("ping from A"))
	if err := tunA.Inject(ping); err != nil {
		t.Fatal(err)
	}
	expectPacket(t, tunB, ping)

	pong := ipv4("10.200.0.2", "10.200.0.1", []byte("pong from B"))
	if err := tunB.Inject(pong); err != nil {
		t.Fatal(err)
	}
	expectPacket(t, tunA, pong)

	var sa, sb device.Session
	var okA, okB bool
	qctx, qcancel := context.WithTimeout(ctx, 5*time.Second)
	defer qcancel()
	if err := nodeA.Query(qctx, func(d *device.Device) { sa, okA = d.Current(pubB) }); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.Query(qctx, func(d *device.Device) { sb, okB = d.Current(pubA) }); err != nil {
		t.Fatal(err)
	}
	if !okA || !okB || sa.SendID != sb.RecvID || sa.RecvID != sb.SendID || !sa.Initiator || sb.Initiator {
		t.Fatalf("sessions do not match: A %+v (%v), B %+v (%v)", sa, okA, sb, okB)
	}
	var epB netip.AddrPort
	if err := nodeB.Query(qctx, func(d *device.Device) { epB, _ = d.Endpoint(pubA) }); err != nil {
		t.Fatal(err)
	}
	if epB != addrA {
		t.Fatalf("B learned endpoint %v, want %v", epB, addrA)
	}
	if s := nodeA.Stats(); s.DatagramsOut < 2 || s.PacketsIn != 1 || s.PacketsOut != 1 {
		t.Fatalf("A stats %+v", s)
	}
}

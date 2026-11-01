package props

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/CesarManzoCode/malla-wg/internal/device"
	"github.com/CesarManzoCode/malla-wg/internal/noise"
	"github.com/CesarManzoCode/malla-wg/sim"
)

// Parameters of the crossed-handshake batch, contract §6.
const (
	crossDeadline int64 = 60e9
	crossSendEnd  int64 = 55e9 // last data packet
	crossLateFrom int64 = 30e9 // data sent from here on must arrive
	crossInterval int64 = 250 * sim.Ms
	crossWall     int64 = 1_793_000_000 * 1e9
	crossPort           = 51820
)

var crossLoss = [3]float64{0, 0.05, 0.2}

var (
	innerA = netip.MustParseAddr("10.0.0.1")
	innerB = netip.MustParseAddr("10.0.0.2")
)

type crossResult struct {
	log        []byte
	a, b       *sim.DeviceNode
	pubA, pubB [noise.KeySize]byte
	// lateA and lateB count the data packets each side received that were
	// sent at or after crossLateFrom.
	lateA, lateB int
}

// crossScenario runs the crossed-handshake scenario of seed: both devices
// start within 50 ms of each other with a packet for the other, so both
// initiate, and keep sending one packet every 250 ms until 55 s. A device
// starts by binding its port: datagrams that arrive earlier are dropped
// (no_port), so neither can complete a handshake before its own start.
func crossScenario(t *testing.T, seed uint64) *crossResult {
	t.Helper()
	var buf bytes.Buffer
	s := sim.New(seed, &buf)
	params := rand.New(s.Stream())
	link := sim.LinkConfig{
		Latency: 5*sim.Ms + params.Int64N(75*sim.Ms+1),
		Jitter:  params.Int64N(30*sim.Ms + 1),
		Loss:    crossLoss[seed%3],
	}
	startA, startB := params.Int64N(50*sim.Ms+1), params.Int64N(50*sim.Ms+1)

	ha := s.NewHost("a", netip.MustParseAddr("192.0.2.1"))
	hb := s.NewHost("b", netip.MustParseAddr("198.51.100.2"))
	s.Connect(ha, hb, link)
	privA, err := noise.GeneratePrivateKey(ha.Rand)
	if err != nil {
		t.Fatal(err)
	}
	privB, err := noise.GeneratePrivateKey(hb.Rand)
	if err != nil {
		t.Fatal(err)
	}
	r := &crossResult{pubA: noise.NewLocal(privA).PublicKey(), pubB: noise.NewLocal(privB).PublicKey()}
	boot(t, s, &r.a, &r.lateA, startA, ha, device.Config{PrivateKey: privA, WallOffset: crossWall,
		Peers: []device.PeerConfig{{PublicKey: r.pubB, AllowedIPs: []netip.Prefix{netip.PrefixFrom(innerB, 32)}, Endpoint: hb.AddrPort(crossPort)}}},
		innerA, innerB)
	boot(t, s, &r.b, &r.lateB, startB, hb, device.Config{PrivateKey: privB, WallOffset: crossWall + 11e9,
		Peers: []device.PeerConfig{{PublicKey: r.pubA, AllowedIPs: []netip.Prefix{netip.PrefixFrom(innerA, 32)}, Endpoint: ha.AddrPort(crossPort)}}},
		innerB, innerA)
	if err := s.RunUntil(crossDeadline); err != nil {
		t.Fatal(err)
	}
	r.log = buf.Bytes()
	return r
}

// boot starts a device from cfg on h at start, stores it in *n, counts
// its late packets in *late and schedules its traffic from src to dst.
func boot(t *testing.T, s *sim.Sim, n **sim.DeviceNode, late *int, start int64, h *sim.Host, cfg device.Config, src, dst netip.Addr) {
	s.At(start, func() {
		var err error
		if *n, err = sim.AttachDevice(h, crossPort, cfg); err != nil {
			t.Fatal(err)
		}
		(*n).OnTUN = func(p []byte) { *late += latePacket(p) }
		traffic(s, *n, start, src, dst)
	})
}

// traffic schedules n's packets from src to dst, each carrying its send
// time.
func traffic(s *sim.Sim, n *sim.DeviceNode, start int64, src, dst netip.Addr) {
	for at := start; at <= crossSendEnd; at += crossInterval {
		var payload [8]byte
		binary.BigEndian.PutUint64(payload[:], uint64(at))
		s.At(at, func() { n.Inject(sim.IPv4Packet(src, dst, payload[:])) })
	}
}

func latePacket(pkt []byte) int {
	if len(pkt) >= 28 && int64(binary.BigEndian.Uint64(pkt[20:28])) >= crossLateFrom {
		return 1
	}
	return 0
}

func initiated(n *sim.DeviceNode) bool {
	for _, e := range n.Events {
		if e.Kind == device.EventRekey {
			return true
		}
	}
	return false
}

// checkCross returns what the scenario's outcome violates, or "".
func checkCross(r *crossResult) string {
	if !initiated(r.a) || !initiated(r.b) {
		return fmt.Sprintf("not both sides initiated (a: %v, b: %v)", initiated(r.a), initiated(r.b))
	}
	ka, okA := r.a.Dev.Current(r.pubB)
	kb, okB := r.b.Dev.Current(r.pubA)
	if !okA || !okB {
		return fmt.Sprintf("no current keypair at 60 s (a: %v, b: %v)", okA, okB)
	}
	if ka.LocalIndex != kb.RemoteIndex || ka.RemoteIndex != kb.LocalIndex || ka.Initiator == kb.Initiator {
		return fmt.Sprintf("current keypairs are not one session: a %+v, b %+v", ka, kb)
	}
	if ka.SendID != kb.RecvID || ka.RecvID != kb.SendID {
		return "current keypairs do not match: a's sending key is not b's receiving key or vice versa"
	}
	if r.lateA == 0 || r.lateB == 0 {
		return fmt.Sprintf("data does not flow both ways after 30 s: a received %d, b received %d", r.lateA, r.lateB)
	}
	return ""
}

// TestCritCrossHandshakes is criterion 11: with both sides initiating,
// every seed of the batch ends with one coherent current keypair on each
// side and data flowing both ways.
func TestCritCrossHandshakes(t *testing.T) {
	for _, seed := range sim.Seeds(1, 32) {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			if msg := checkCross(crossScenario(t, seed)); msg != "" {
				sim.Fatal(t, seed, "%s", msg)
			}
		})
	}
}

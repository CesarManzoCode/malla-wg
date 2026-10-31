package sim

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/netip"

	"github.com/CesarManzoCode/malla-wg/internal/device"
	"github.com/CesarManzoCode/malla-wg/internal/noise"
)

// DeviceNode runs an internal/device on a port of a host: it hands the
// device the datagrams that reach the port, calls Tick at NextDeadline,
// sends what the device emits and keeps what it writes to its TUN.
type DeviceNode struct {
	Host *Host
	Port uint16
	Dev  *device.Device

	// TUN holds the packets the device wrote to its TUN, in order; OnTUN,
	// if set, is called with each one as well.
	TUN   [][]byte
	OnTUN func(pkt []byte)
	// Events holds every event the device reported, in order.
	Events []device.Event

	timerAt  int64
	timerOn  bool
	timerGen uint64
}

// AttachDevice creates a device from cfg on port of h. The device's
// randomness is the host's stream: cfg.Rand is replaced by h.Rand.
func AttachDevice(h *Host, port uint16, cfg device.Config) (*DeviceNode, error) {
	cfg.Rand = h.Rand
	dev, err := device.New(cfg)
	if err != nil {
		return nil, err
	}
	n := &DeviceNode{Host: h, Port: port, Dev: dev}
	h.s.net.names(dev.PublicKey(), h.Name)
	h.Listen(port, func(src, _ netip.AddrPort, data []byte) {
		n.absorb(n.Dev.HandleUDP(h.s.now, src, data))
	})
	n.rearm()
	return n, nil
}

// Inject hands pkt to the device as if read from its TUN, now.
func (n *DeviceNode) Inject(pkt []byte) {
	n.Host.s.Log(Record{Ev: "inject", Node: n.Host.Name, Len: len(pkt)})
	n.absorb(n.Dev.HandleTUN(n.Host.s.now, bytes.Clone(pkt)))
}

// absorb logs and carries out one output of the device: events first,
// then TUN packets, then datagrams, each in the device's order.
func (n *DeviceNode) absorb(out device.Output) {
	s := n.Host.s
	for _, e := range out.Events {
		n.Events = append(n.Events, e)
		r := Record{Ev: e.Kind.String(), Node: n.Host.Name, Reason: e.Reason, Peer: s.net.peerName(e.Peer)}
		if e.Kind == device.EventDrop {
			r.Ev = "wg_drop"
		}
		if e.Kind == device.EventEndpoint {
			r.Dst = e.Endpoint.String()
		}
		s.Log(r)
	}
	for _, p := range out.Packets {
		s.Log(Record{Ev: "tun", Node: n.Host.Name, Len: len(p)})
		n.TUN = append(n.TUN, p)
		if n.OnTUN != nil {
			n.OnTUN(p)
		}
	}
	for _, d := range out.Datagrams {
		n.Host.Send(n.Port, d.Dst, d.Data)
	}
	n.rearm()
}

// rearm schedules a Tick at the device's next deadline. A timer event that
// was superseded finds a newer generation and does nothing.
func (n *DeviceNode) rearm() {
	at := n.Dev.NextDeadline()
	if at == device.Never {
		n.timerOn = false
		n.timerGen++
		return
	}
	if n.timerOn && at == n.timerAt {
		return
	}
	n.timerGen++
	n.timerOn, n.timerAt = true, at
	gen, s := n.timerGen, n.Host.s
	s.At(at, func() {
		if n.timerGen != gen {
			return
		}
		n.timerOn = false
		s.Log(Record{Ev: "timer", Node: n.Host.Name})
		n.absorb(n.Dev.Tick(s.now))
	})
}

// names records which host runs the device with public key pub, so the log
// names peers by host.
func (n *network) names(pub [noise.KeySize]byte, host string) {
	if n.keys == nil {
		n.keys = make(map[[noise.KeySize]byte]string)
	}
	n.keys[pub] = host
}

func (n *network) peerName(pub [noise.KeySize]byte) string {
	if pub == ([noise.KeySize]byte{}) {
		return ""
	}
	if name, ok := n.keys[pub]; ok {
		return name
	}
	return hex.EncodeToString(pub[:4])
}

// IPv4Packet builds a minimal IPv4/UDP-protocol packet from src to dst
// carrying payload, enough for the device's allowed-IPs routing.
func IPv4Packet(src, dst netip.Addr, payload []byte) []byte {
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

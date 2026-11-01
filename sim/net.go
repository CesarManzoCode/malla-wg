package sim

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"net/netip"
)

// Drop reasons of the network, from the contract §5. The NATs add their
// own (DropNATFilter, DropNoMapping).
const (
	DropLoss    = "loss"
	DropNoRoute = "no_route"
	DropNoPort  = "no_port" // the destination host does not listen on the port
)

// Packet is a UDP datagram in flight.
type Packet struct {
	Src, Dst netip.AddrPort
	Data     []byte
}

// Middlebox sees every datagram as it leaves its sending host, before it is
// routed by destination address, and may rewrite its addresses (NATs) or
// drop it by returning a non-empty reason. Middleboxes run in the order of
// AddMiddlebox.
type Middlebox interface {
	Process(now int64, from *Host, p *Packet) (drop string)
}

// Handler receives the datagrams delivered to a port of a host.
type Handler func(src, dst netip.AddrPort, data []byte)

// Host is a simulated machine with one address.
type Host struct {
	s    *Sim
	Name string
	Addr netip.Addr
	// Rand is the host's own random stream, for its keys and its device.
	Rand  *rand.ChaCha8
	ports map[uint16]Handler
}

// LinkConfig describes a link: every datagram is lost with probability Loss
// and otherwise delivered after Latency plus a jitter uniform in
// [0, Jitter], so datagrams can be reordered.
type LinkConfig struct {
	Latency, Jitter int64
	Loss            float64
}

// Link is a bidirectional link between two hosts.
type Link struct {
	cfg LinkConfig
	rnd *rand.Rand
}

type hostPair [2]*Host

type network struct {
	hosts  []*Host
	byAddr map[netip.Addr]*Host
	links  map[hostPair]*Link
	boxes  []Middlebox
	keys   map[[32]byte]string // device public key → host name
	nat    *natTable           // the middlebox of every NAT, once there is one
}

func (n *network) init() {
	n.byAddr = make(map[netip.Addr]*Host)
	n.links = make(map[hostPair]*Link)
}

// NewHost adds a host named name with address addr and draws its random
// stream. Names and addresses must be unique.
func (s *Sim) NewHost(name string, addr netip.Addr) *Host {
	if _, dup := s.net.byAddr[addr]; dup {
		panic(fmt.Sprintf("sim: address %v already in use", addr))
	}
	for _, h := range s.net.hosts {
		if h.Name == name {
			panic(fmt.Sprintf("sim: host name %q already in use", name))
		}
	}
	h := &Host{s: s, Name: name, Addr: addr, Rand: s.Stream(), ports: make(map[uint16]Handler)}
	s.net.hosts = append(s.net.hosts, h)
	s.net.byAddr[addr] = h
	return h
}

// Connect links a and b in both directions and draws the link's random
// stream.
func (s *Sim) Connect(a, b *Host, cfg LinkConfig) *Link {
	if cfg.Latency < 0 || cfg.Jitter < 0 || cfg.Loss < 0 || cfg.Loss > 1 {
		panic(fmt.Sprintf("sim: invalid link %+v", cfg))
	}
	l := &Link{cfg: cfg, rnd: rand.New(s.Stream())}
	s.net.links[hostPair{a, b}] = l
	s.net.links[hostPair{b, a}] = l
	return l
}

// AddMiddlebox appends m to the path of every datagram.
func (s *Sim) AddMiddlebox(m Middlebox) { s.net.boxes = append(s.net.boxes, m) }

// sample draws the fate of one datagram. It always consumes the same
// amount of randomness, lost or not.
func (l *Link) sample() (lost bool, delay int64) {
	lost = l.rnd.Float64() < l.cfg.Loss
	delay = l.cfg.Latency
	if l.cfg.Jitter > 0 {
		delay += l.rnd.Int64N(l.cfg.Jitter + 1)
	}
	return lost, delay
}

// Listen delivers the datagrams that reach port to fn.
func (h *Host) Listen(port uint16, fn Handler) { h.ports[port] = fn }

// AddrPort returns the host's address with port.
func (h *Host) AddrPort(port uint16) netip.AddrPort { return netip.AddrPortFrom(h.Addr, port) }

// Send sends data from port of h to dst now.
func (h *Host) Send(port uint16, dst netip.AddrPort, data []byte) {
	s := h.s
	p := Packet{Src: h.AddrPort(port), Dst: dst, Data: bytes.Clone(data)}
	s.Log(Record{Ev: "send", Node: h.Name, Src: p.Src.String(), Dst: p.Dst.String(), Len: len(p.Data)})
	for _, m := range s.net.boxes {
		if r := m.Process(s.now, h, &p); r != "" {
			s.logDrop(h, p, r)
			return
		}
	}
	to := s.net.byAddr[p.Dst.Addr()]
	link := s.net.links[hostPair{h, to}]
	if to == nil || link == nil {
		s.logDrop(h, p, DropNoRoute)
		return
	}
	lost, delay := link.sample()
	if lost {
		s.logDrop(h, p, DropLoss)
		return
	}
	s.After(delay, func() {
		fn := to.ports[p.Dst.Port()]
		if fn == nil {
			s.logDrop(to, p, DropNoPort)
			return
		}
		s.Log(Record{Ev: "deliver", Node: to.Name, Src: p.Src.String(), Dst: p.Dst.String(), Len: len(p.Data)})
		fn(p.Src, p.Dst, p.Data)
	})
}

func (s *Sim) logDrop(at *Host, p Packet, reason string) {
	s.Log(Record{Ev: "drop", Node: at.Name, Src: p.Src.String(), Dst: p.Dst.String(), Len: len(p.Data), Reason: reason})
}

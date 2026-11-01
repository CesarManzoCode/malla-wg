package sim

import (
	"fmt"
	"net/netip"
	"strings"
)

// Mapping is the mapping behavior of a NAT (RFC 4787 §4.1): whether an
// internal endpoint keeps its external port toward every destination (EIM),
// gets one per destination address (ADM) or one per destination address
// and port (APDM).
type Mapping uint8

// Mapping behaviors, from least to most restrictive.
const (
	EIM Mapping = iota
	ADM
	APDM
)

func (m Mapping) String() string { return [...]string{"EIM", "ADM", "APDM"}[m] }

// Filtering is the filtering behavior of a NAT (RFC 4787 §5): which
// outside endpoints may send to an external port. The contract §4.1 keeps
// the filter state per mapping.
type Filtering uint8

// Filtering behaviors, from least to most restrictive.
const (
	EIF Filtering = iota
	ADF
	APDF
)

func (f Filtering) String() string { return [...]string{"EIF", "ADF", "APDF"}[f] }

// ParseNATType parses a NAT type name of the contract §4.1, such as
// "EIM-ADF". The type "none" is a public host and has no NAT.
func ParseNATType(s string) (Mapping, Filtering, error) {
	ms, fs, _ := strings.Cut(s, "-")
	m, f := -1, -1
	for i, name := range [...]string{"EIM", "ADM", "APDM"} {
		if ms == name {
			m = i
		}
	}
	for i, name := range [...]string{"EIF", "ADF", "APDF"} {
		if fs == name {
			f = i
		}
	}
	if m < 0 || f < 0 {
		return 0, 0, fmt.Errorf("sim: unknown NAT type %q", s)
	}
	return Mapping(m), Filtering(f), nil
}

// Drop reasons of the NATs, from the contract §5.
const (
	DropNATFilter = "nat_filter" // the mapping's filter rejected the sender
	DropNoMapping = "no_mapping" // no mapping holds the external port
)

// DefaultNATTimeout is the idle timeout of a mapping (REQ-5 of RFC 4787).
const DefaultNATTimeout int64 = 120e9

// NATConfig describes the behavior of a NAT.
type NATConfig struct {
	Mapping   Mapping
	Filtering Filtering
	// Hairpin lets a host inside send to the NAT's own external address;
	// the NAT then presents the sender's external endpoint (REQ-9a).
	Hairpin bool
	// Timeout is the idle timeout of a mapping; 0 means DefaultNATTimeout.
	Timeout int64
	// FirstPort is the first external port handed out; 0 means 1024.
	FirstPort uint16
}

// NAT is a simulated NAT with one external address. The hosts added to it
// and the NATs nested in it are inside; everything else is outside.
type NAT struct {
	s        *Sim
	Name     string
	External netip.Addr
	cfg      NATConfig

	hosts    map[netip.Addr]bool
	children []*NAT
	byKey    map[natKey]*natMapping
	byPort   map[uint16]*natMapping
	next     uint16
}

// natKey identifies a mapping: the internal endpoint and, for ADM and
// APDM, the destination (port 0 for ADM).
type natKey struct{ in, dst netip.AddrPort }

type natMapping struct {
	key   natKey
	port  uint16
	last  int64
	addrs map[netip.Addr]bool     // destination addresses sent to (ADF)
	eps   map[netip.AddrPort]bool // destination endpoints sent to (APDF)
}

// natTable is the one middlebox that carries every NAT of a simulation:
// first the NAT that holds the source translates it outward, innermost
// NAT first, then the NAT that owns the destination address translates it
// inward, outermost first. One hook for all keeps that order independent
// of the order in which the NATs were created.
type natTable struct{ top []*NAT }

func (t *natTable) Process(now int64, _ *Host, p *Packet) string {
	for _, n := range t.top {
		if n.holds(p.Src.Addr()) {
			if r := n.outbound(now, p); r != "" {
				return r
			}
			break
		}
	}
	for _, n := range t.top {
		if p.Dst.Addr() == n.External && !n.holds(p.Src.Addr()) {
			return n.inbound(now, p)
		}
	}
	return ""
}

// NewNAT adds a NAT named name with external address ext on the outside
// of the simulated network.
func (s *Sim) NewNAT(name string, ext netip.Addr, cfg NATConfig) *NAT {
	n := newNAT(s, name, ext, cfg)
	if s.net.nat == nil {
		s.net.nat = &natTable{}
		s.AddMiddlebox(s.net.nat)
	}
	s.net.nat.top = append(s.net.nat.top, n)
	return n
}

// NewNAT nests a NAT inside n, as a home NAT inside a carrier-grade NAT:
// its external address ext is an inside address of n.
func (n *NAT) NewNAT(name string, ext netip.Addr, cfg NATConfig) *NAT {
	c := newNAT(n.s, name, ext, cfg)
	n.children = append(n.children, c)
	return c
}

func newNAT(s *Sim, name string, ext netip.Addr, cfg NATConfig) *NAT {
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultNATTimeout
	}
	if cfg.FirstPort == 0 {
		cfg.FirstPort = 1024
	}
	return &NAT{s: s, Name: name, External: ext, cfg: cfg, next: cfg.FirstPort,
		hosts: make(map[netip.Addr]bool), byKey: make(map[natKey]*natMapping),
		byPort: make(map[uint16]*natMapping)}
}

// Add puts hosts inside n.
func (n *NAT) Add(hosts ...*Host) {
	for _, h := range hosts {
		n.hosts[h.Addr] = true
	}
}

// local reports whether a is directly inside n: a host of n or the
// external address of a nested NAT.
func (n *NAT) local(a netip.Addr) bool {
	if n.hosts[a] {
		return true
	}
	for _, c := range n.children {
		if c.External == a {
			return true
		}
	}
	return false
}

// holds reports whether a is anywhere inside n.
func (n *NAT) holds(a netip.Addr) bool {
	if n.hosts[a] {
		return true
	}
	for _, c := range n.children {
		if c.External == a || c.holds(a) {
			return true
		}
	}
	return false
}

// outbound handles a datagram whose source is inside n.
func (n *NAT) outbound(now int64, p *Packet) string {
	if !n.hosts[p.Src.Addr()] {
		for _, c := range n.children {
			if c.holds(p.Src.Addr()) {
				if r := c.outbound(now, p); r != "" {
					return r
				}
				break
			}
		}
		if !n.local(p.Src.Addr()) {
			return "" // it stayed inside the nested NAT
		}
	}
	dst := p.Dst.Addr()
	for _, c := range n.children {
		if c.External == dst {
			return c.inbound(now, p)
		}
	}
	if n.holds(dst) {
		return "" // between inside segments: routed as addressed
	}
	if dst == n.External && !n.cfg.Hairpin {
		return DropNoRoute
	}
	if r := n.translate(now, p); r != "" {
		return r
	}
	if dst == n.External {
		return n.inbound(now, p) // hairpin, with the external source
	}
	return ""
}

// translate rewrites the source of p to its mapping, creating one if
// needed, and records the destination in the mapping's filter state.
func (n *NAT) translate(now int64, p *Packet) string {
	k := natKey{in: p.Src}
	switch n.cfg.Mapping {
	case ADM:
		k.dst = netip.AddrPortFrom(p.Dst.Addr(), 0)
	case APDM:
		k.dst = p.Dst
	}
	m := n.byKey[k]
	if m == nil {
		port, ok := n.allocate()
		if !ok {
			return DropNoMapping
		}
		m = &natMapping{key: k, port: port, last: now,
			addrs: make(map[netip.Addr]bool), eps: make(map[netip.AddrPort]bool)}
		n.byKey[k], n.byPort[port] = m, m
		n.s.Log(Record{Ev: "nat_map", Node: n.Name, Src: k.in.String(), Dst: n.ext(port).String()})
		n.arm(m)
	}
	m.last = now
	m.addrs[p.Dst.Addr()] = true
	m.eps[p.Dst] = true
	p.Src = n.ext(m.port)
	return ""
}

func (n *NAT) ext(port uint16) netip.AddrPort { return netip.AddrPortFrom(n.External, port) }

// allocate hands out the next free external port, in order from
// FirstPort and wrapping around, so allocation is deterministic.
func (n *NAT) allocate() (uint16, bool) {
	for range 65536 - int(n.cfg.FirstPort) {
		p := max(n.next, n.cfg.FirstPort)
		n.next = p + 1
		if n.byPort[p] == nil {
			return p, true
		}
	}
	return 0, false
}

// arm schedules the idle check of m. A mapping keeps one pending check,
// which moves forward if the mapping was used since.
func (n *NAT) arm(m *natMapping) {
	n.s.At(m.last+n.cfg.Timeout, func() {
		if n.byPort[m.port] != m {
			return
		}
		if n.s.now < m.last+n.cfg.Timeout {
			n.arm(m)
			return
		}
		delete(n.byPort, m.port)
		delete(n.byKey, m.key)
		n.s.Log(Record{Ev: "nat_expire", Node: n.Name, Src: m.key.in.String(), Dst: n.ext(m.port).String()})
	})
}

// inbound handles a datagram addressed to n's external address.
func (n *NAT) inbound(now int64, p *Packet) string {
	m := n.byPort[p.Dst.Port()]
	if m == nil {
		return DropNoMapping
	}
	switch n.cfg.Filtering {
	case ADF:
		if !m.addrs[p.Src.Addr()] {
			return DropNATFilter
		}
	case APDF:
		if !m.eps[p.Src] {
			return DropNATFilter
		}
	}
	m.last = now
	p.Dst = m.key.in
	for _, c := range n.children {
		if c.External == p.Dst.Addr() {
			return c.inbound(now, p)
		}
	}
	return ""
}

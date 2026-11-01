package sim

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/coord"
	"github.com/CesarManzoCode/malla-wg/internal/device"
	"github.com/CesarManzoCode/malla-wg/internal/magic"
	"github.com/CesarManzoCode/malla-wg/internal/mesh"
	"github.com/CesarManzoCode/malla-wg/internal/noise"
	"github.com/CesarManzoCode/malla-wg/internal/relay"
)

// The mesh inside the simulator: nodes of internal/mesh, the coordination
// and the relay. Their rules are the product's (mesh.Core, coord.Core,
// relay.Core and its frames); the simulator only carries their messages.
// Coordination requests and replies and relay frames arrive one base
// latency of the link between the two hosts later, without loss and in
// order, as over TCP; the reflexive service and the nodes' datagrams
// cross the simulated network and its NATs.

// meshWall is the wall clock of every mesh node at now = 0, for TAI64N.
const meshWall int64 = 1_793_000_000 * 1e9

// Timings of the simulated node's coordination loop. The reflexive
// request is repeated until it is answered, so that a lost datagram does
// not leave the node without its reflexive endpoint for 30 s.
const (
	reflexiveRetry  int64 = 1e9
	rediscoverEvery int64 = 30e9
	coordRetry      int64 = 1e9
)

// latency returns the base latency of the link between a and b, on which
// the reliable channels of the coordination and the relay ride.
func (s *Sim) latency(a, b *Host) int64 {
	l := s.net.links[hostPair{a, b}]
	if l == nil {
		panic(fmt.Sprintf("sim: no link between %s and %s", a.Name, b.Name))
	}
	return l.cfg.Latency
}

// Coord is the coordination inside the simulator: coord.Core behind
// messages with latency, long-polls included, and the reflexive endpoint
// service on port coord.DefaultReflexivePort of its host.
type Coord struct {
	Host  *Host
	Core  *coord.Core
	polls []*pendingPoll
}

type pendingPoll struct {
	node  *MeshNode
	token string
	done  bool
}

// NewCoord runs a coordination with cfg on h. Its randomness (tokens) is
// the host's stream.
func (s *Sim) NewCoord(h *Host, cfg coord.CoreConfig) (*Coord, error) {
	core, err := coord.NewCore(cfg, nil)
	if err != nil {
		return nil, err
	}
	h.Listen(coord.DefaultReflexivePort, func(src, _ netip.AddrPort, data []byte) {
		if resp, ok := coord.ReflexiveReply(data, src); ok {
			h.Send(coord.DefaultReflexivePort, src, resp)
		}
	})
	return &Coord{Host: h, Core: core}, nil
}

// call runs fn at the coordination one latency after now and the reply fn
// returns, if any, at the node one latency later.
func (c *Coord) call(n *MeshNode, fn func() func()) {
	s := c.Host.s
	lat := s.latency(n.Host, c.Host)
	s.After(lat, func() {
		if reply := fn(); reply != nil {
			s.After(lat, reply)
		}
	})
}

// changed answers every pending long-poll: the map's version went up.
func (c *Coord) changed() {
	polls := c.polls
	c.polls = nil
	for _, p := range polls {
		p.done = true
		c.answer(p.node, p.token)
	}
}

// poll is GET /v1/netmap?since: the map now if it is newer than since,
// else at the next change or after coord.LongPoll.
func (c *Coord) poll(n *MeshNode, token string, since uint64) {
	if c.Core.Version() > since {
		c.answer(n, token)
		return
	}
	p := &pendingPoll{node: n, token: token}
	c.polls = append(c.polls, p)
	c.Host.s.After(int64(coord.LongPoll), func() {
		if p.done {
			return
		}
		p.done = true
		c.polls = slices.DeleteFunc(c.polls, func(q *pendingPoll) bool { return q == p })
		c.answer(n, token)
	})
}

func (c *Coord) answer(n *MeshNode, token string) {
	nm, err := c.Core.Netmap(token)
	s := c.Host.s
	s.After(s.latency(n.Host, c.Host), func() { n.netmap(nm, err) })
}

// Relay is the relay inside the simulator: relay.Core decides over the
// frames of contract §3.2, and every connection is a reliable, ordered
// channel between a node and the relay's host.
type Relay struct {
	Host  *Host
	Core  *relay.Core
	conns map[relay.ConnID]*MeshNode
	next  relay.ConnID
}

// NewRelay runs a relay on h.
func (s *Sim) NewRelay(h *Host) *Relay {
	return &Relay{Host: h, Core: relay.NewCore(), conns: make(map[relay.ConnID]*MeshNode)}
}

func (r *Relay) open(n *MeshNode) relay.ConnID {
	r.next++
	r.conns[r.next] = n
	return r.next
}

// frame handles one frame of connection id. A frame that breaks the
// protocol closes the connection, as relay.Server does.
func (r *Relay) frame(id relay.ConnID, b []byte) {
	if r.conns[id] == nil {
		return
	}
	t, payload, k, err := relay.ParseFrame(b)
	if err == nil && k != len(b) {
		err = relay.ErrMalformed
	}
	var res relay.Result
	if err == nil {
		res, err = r.Core.Handle(id, t, payload)
	}
	if err != nil {
		r.close(id)
		return
	}
	for _, cid := range res.Close {
		r.close(cid)
	}
	s := r.Host.s
	for _, o := range res.Out {
		if n := r.conns[o.To]; n != nil {
			s.After(s.latency(n.Host, r.Host), func() { n.fromRelay(o.To, o.Frame) })
		}
	}
}

func (r *Relay) close(id relay.ConnID) {
	n := r.conns[id]
	delete(r.conns, id)
	r.Core.Closed(id)
	if n != nil {
		s := r.Host.s
		s.After(s.latency(n.Host, r.Host), func() { n.relayClosed(id) })
	}
}

// MeshConfig describes a mesh node.
type MeshConfig struct {
	Name    string // the node's name at the coordination
	Port    uint16 // the WireGuard and disco port
	AuthKey string
	Coord   *Coord
	Relay   *Relay // nil: no relay
	// PersistentKeepalive is given to every peer of the map.
	PersistentKeepalive time.Duration
}

// MeshNode runs a mesh.Core on a port of a host: it registers with the
// coordination, asks the reflexive service for its endpoint, reports its
// endpoints, follows the map by long-poll, keeps a relay connection, and
// calls the core's Tick at NextDeadline. Every change of a peer's path is
// logged as a path event.
type MeshNode struct {
	Host *Host
	Port uint16
	Core *mesh.Core

	// TUN holds the packets the node wrote to its TUN, in order; OnTUN, if
	// set, is called with each one as well.
	TUN   [][]byte
	OnTUN func(pkt []byte)
	// Events holds every event of the node's device, in order.
	Events []device.Event
	// OnPath, if set, is called after the path of some peer changed.
	OnPath func()

	cfg         MeshConfig
	addr        netip.Addr
	token       string
	since       uint64
	reported    []netip.AddrPort
	hasReported bool
	txid        [12]byte
	asking      bool
	relayID     relay.ConnID
	paths       map[[32]byte]magic.Path

	timerAt  int64
	timerOn  bool
	timerGen uint64
}

// AttachMesh starts a mesh node on h. Its keys and randomness come from
// the host's stream.
func AttachMesh(h *Host, cfg MeshConfig) (*MeshNode, error) {
	priv, err := noise.GeneratePrivateKey(h.Rand)
	if err != nil {
		return nil, err
	}
	disco, err := noise.GeneratePrivateKey(h.Rand)
	if err != nil {
		return nil, err
	}
	core, err := mesh.NewCore(mesh.CoreConfig{PrivateKey: priv, DiscoKey: disco, Rand: h.Rand,
		WallOffset: meshWall, PersistentKeepalive: cfg.PersistentKeepalive})
	if err != nil {
		return nil, err
	}
	n := &MeshNode{Host: h, Port: cfg.Port, Core: core, cfg: cfg, paths: make(map[[32]byte]magic.Path)}
	h.s.net.names(core.PublicKey(), h.Name)
	h.Listen(cfg.Port, n.udp)
	if cfg.Relay != nil {
		n.relayID = cfg.Relay.open(n)
		pub := core.PublicKey()
		n.toRelay(relay.AppendFrame(nil, relay.TypeClientHello, pub[:]))
	}
	n.register()
	n.rearm()
	return n, nil
}

// Addr returns the node's mesh address, invalid before it registered.
func (n *MeshNode) Addr() netip.Addr { return n.addr }

// Path returns how n reaches peer now, as `malla status` reports it.
func (n *MeshNode) Path(peer *MeshNode) magic.Path {
	return n.Core.Path(n.Host.s.now, peer.Core.PublicKey())
}

// Inject hands pkt to the node as if read from its TUN, now.
func (n *MeshNode) Inject(pkt []byte) {
	n.Host.s.Log(Record{Ev: "inject", Node: n.Host.Name, Len: len(pkt)})
	n.absorb(n.Core.HandleTUN(n.Host.s.now, bytes.Clone(pkt)))
}

func (n *MeshNode) logf(format string, args ...any) {
	n.Host.s.Log(Record{Ev: "mesh", Node: n.Host.Name, Reason: fmt.Sprintf(format, args...)})
}

// udp takes what reaches the node's port: the reflexive service's replies
// for the node, everything else for the core.
func (n *MeshNode) udp(src, _ netip.AddrPort, data []byte) {
	if !coord.IsReflexive(data) {
		n.absorb(n.Core.HandleUDP(n.Host.s.now, src, data))
		return
	}
	if txid, addr, ok := coord.ParseReflexiveReply(data); ok && n.asking && txid == n.txid {
		n.asking = false
		n.report(addr)
		n.Host.s.After(rediscoverEvery, n.discover)
	}
}

func (n *MeshNode) register() {
	c := n.cfg.Coord
	req := coord.RegisterRequest{AuthKey: n.cfg.AuthKey, NodeKey: coord.Key(n.Core.PublicKey()),
		DiscoKey: coord.Key(n.Core.DiscoPublic()), Name: n.cfg.Name}
	c.call(n, func() func() {
		resp, err := c.Core.Register(req, c.Host.Rand)
		if err == nil {
			c.changed()
		}
		return func() {
			if err != nil {
				n.logf("register: %v", err)
				n.Host.s.After(coordRetry, n.register)
				return
			}
			n.addr, n.token, n.since = resp.Addr, resp.Token, 0
			n.discover()
			n.poll()
		}
	})
}

// discover asks the reflexive service, from the node's port, which
// endpoint it sees, again every reflexiveRetry until it answers.
func (n *MeshNode) discover() {
	if _, err := io.ReadFull(n.Host.Rand, n.txid[:]); err != nil {
		return
	}
	n.asking = true
	txid := n.txid
	n.Host.Send(n.Port, n.cfg.Coord.Host.AddrPort(coord.DefaultReflexivePort), coord.ReflexiveRequest(txid))
	n.Host.s.After(reflexiveRetry, func() {
		if n.asking && n.txid == txid {
			n.discover()
		}
	})
}

// report gives the coordination and the core the node's endpoints
// (magic.Endpoints of the reflexive one and the host's address) if they
// changed since the last report.
func (n *MeshNode) report(reflexive netip.AddrPort) {
	eps := magic.Endpoints(reflexive, []netip.Addr{n.Host.Addr}, n.Port, coord.MeshPrefix)
	if n.hasReported && !magic.EndpointsChanged(n.reported, eps) {
		return
	}
	n.reported, n.hasReported = eps, true
	n.Core.SetEndpoints(eps)
	strs := make([]string, len(eps))
	for i, ap := range eps {
		strs[i] = ap.String()
	}
	c, token := n.cfg.Coord, n.token
	c.call(n, func() func() {
		if err := c.Core.SetEndpoints(token, strs); err != nil {
			return func() { n.logf("endpoints: %v", err) }
		}
		c.changed()
		return nil
	})
}

func (n *MeshNode) poll() {
	c, token, since := n.cfg.Coord, n.token, n.since
	c.call(n, func() func() { c.poll(n, token, since); return nil })
}

// netmap applies a map the long-poll returned and polls again.
func (n *MeshNode) netmap(nm coord.Netmap, err error) {
	if err != nil {
		n.logf("netmap: %v", err)
		n.Host.s.After(coordRetry, n.poll)
		return
	}
	n.since = nm.Version
	if err := n.Core.ApplyNetmap(nm, n.logf); err != nil {
		n.logf("%v", err)
	}
	n.absorb(mesh.Output{})
	n.poll()
}

func (n *MeshNode) toRelay(frame []byte) {
	r, id, s := n.cfg.Relay, n.relayID, n.Host.s
	s.After(s.latency(n.Host, r.Host), func() { r.frame(id, frame) })
}

// fromRelay takes a frame of the node's relay connection id.
func (n *MeshNode) fromRelay(id relay.ConnID, b []byte) {
	if id != n.relayID {
		return
	}
	t, payload, _, err := relay.ParseFrame(b)
	if err != nil {
		return
	}
	switch t {
	case relay.TypeServerHello:
		n.Core.SetRelay(true)
		n.absorb(mesh.Output{})
	case relay.TypeRecvPacket:
		if key, dg, err := relay.SplitPacket(payload); err == nil {
			n.absorb(n.Core.HandleRelay(n.Host.s.now, key, bytes.Clone(dg)))
		}
	}
}

func (n *MeshNode) relayClosed(id relay.ConnID) {
	if id == n.relayID {
		n.Core.SetRelay(false)
		n.absorb(mesh.Output{})
	}
}

// absorb logs and carries out one output of the core: events, TUN packets,
// then transmits, each in the core's order; then it logs the paths that
// changed and rearms the timer.
func (n *MeshNode) absorb(out mesh.Output) {
	s := n.Host.s
	n.Events = append(n.Events, out.Events...)
	s.logEvents(n.Host, out.Events)
	for _, p := range out.Packets {
		s.Log(Record{Ev: "tun", Node: n.Host.Name, Len: len(p)})
		n.TUN = append(n.TUN, p)
		if n.OnTUN != nil {
			n.OnTUN(p)
		}
	}
	for _, t := range out.Transmits {
		if !t.Relay {
			n.Host.Send(n.Port, t.Dst, t.Data)
			continue
		}
		if n.cfg.Relay != nil {
			s.Log(Record{Ev: "relay", Node: n.Host.Name, Len: len(t.Data), Peer: s.net.peerName(t.RelayTo)})
			n.toRelay(relay.AppendFrame(nil, relay.TypeSendPacket, t.RelayTo[:], t.Data))
		}
	}
	n.logPaths()
	n.rearm()
}

// logPaths logs a path event for every peer whose path changed.
func (n *MeshNode) logPaths() {
	s := n.Host.s
	changed := false
	for _, st := range n.Core.Status(s.now) {
		if old, ok := n.paths[st.Key]; ok && old == st.Path {
			continue
		}
		n.paths[st.Key] = st.Path
		r := Record{Ev: "path", Node: n.Host.Name, Reason: st.Path.String(), Peer: s.net.peerName(st.Key)}
		if st.Endpoint.IsValid() {
			r.Dst = st.Endpoint.String()
		}
		s.Log(r)
		changed = true
	}
	if changed && n.OnPath != nil {
		n.OnPath()
	}
}

// rearm schedules a Tick at the core's next deadline, as DeviceNode does.
func (n *MeshNode) rearm() {
	at := n.Core.NextDeadline()
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
		n.absorb(n.Core.Tick(s.now))
	})
}

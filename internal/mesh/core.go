package mesh

import (
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/coord"
	"github.com/CesarManzoCode/malla-wg/internal/device"
	"github.com/CesarManzoCode/malla-wg/internal/magic"
	"github.com/CesarManzoCode/malla-wg/internal/x25519"
)

// Core is a mesh node without I/O: the WireGuard device, the bind of
// internal/magic between it and the network, and the rule that keeps the
// device's peers equal to those of the coordination's map. Like the device
// and the bind it reads no clock, opens no socket and starts no
// goroutine; the caller passes now, carries the transmits out and calls
// Tick at NextDeadline. The simulator runs nodes of the mesh on it
// (sim.MeshNode); Node runs the same pieces on the runtime's sockets and
// shares applyPeers with it.
type Core struct {
	dev       *device.Device
	bind      *magic.Bind
	pub       [32]byte
	keepalive time.Duration
}

// CoreConfig describes a Core.
type CoreConfig struct {
	PrivateKey [32]byte
	// DiscoKey is the node's disco private key; the coordination must
	// publish its public half (DiscoPublic) in the map.
	DiscoKey [32]byte
	// Rand feeds the device's keys and indices and the bind's nonces and
	// txids.
	Rand io.Reader
	// WallOffset and MTU are the device's (device.Config).
	WallOffset int64
	MTU        int
	// PersistentKeepalive is given to every peer of the map; 0 disables
	// it, as in Node.
	PersistentKeepalive time.Duration
}

// Output is what one call of Core produces: datagrams for the UDP socket
// or the relay, packets for the TUN and the device's events, each in the
// order they happened.
type Output struct {
	Transmits []magic.Transmit
	Packets   [][]byte
	Events    []device.Event
}

// NewCore returns a node with no peers, no relay and no endpoints.
func NewCore(cfg CoreConfig) (*Core, error) {
	if cfg.Rand == nil {
		return nil, errors.New("mesh: CoreConfig.Rand is nil")
	}
	dev, err := device.New(device.Config{
		PrivateKey: cfg.PrivateKey, Rand: cfg.Rand, WallOffset: cfg.WallOffset, MTU: cfg.MTU,
	})
	if err != nil {
		return nil, err
	}
	c := &Core{dev: dev, bind: magic.New(), pub: x25519.PublicKey(cfg.PrivateKey), keepalive: cfg.PersistentKeepalive}
	c.bind.SetDisco(cfg.DiscoKey, c.pub, cfg.Rand)
	c.bind.SetExclude(coord.MeshPrefix)
	return c, nil
}

// PublicKey returns the node's WireGuard public key.
func (c *Core) PublicKey() [32]byte { return c.pub }

// DiscoPublic returns the node's disco public key.
func (c *Core) DiscoPublic() [32]byte { return c.bind.DiscoPublic() }

// Device returns the device, for tests that inspect its sessions.
func (c *Core) Device() *device.Device { return c.dev }

// ApplyNetmap makes the device's peers those of nm, as Node does with each
// map it receives. A map for another node key is an error and changes
// nothing; the problems with single peers go to logf, which may be nil.
func (c *Core) ApplyNetmap(nm coord.Netmap, logf func(string, ...any)) error {
	if nm.Self.NodeKey != coord.Key(c.pub) {
		return errors.New("mesh: netmap for another node key")
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	applyPeers(c.dev, c.bind, nm.Peers, c.keepalive, logf)
	return nil
}

// SetEndpoints records the node's own endpoints, which CallMeMaybe
// carries (magic.Bind.SetEndpoints).
func (c *Core) SetEndpoints(eps []netip.AddrPort) { c.bind.SetEndpoints(eps) }

// SetRelay records whether the relay connection is up.
func (c *Core) SetRelay(up bool) { c.bind.SetRelay(up) }

// HandleUDP takes a datagram the socket received from src: disco goes to
// the bind, everything else to the device under the source the bind
// translates it to.
func (c *Core) HandleUDP(now int64, src netip.AddrPort, data []byte) Output {
	if magic.IsDisco(data) {
		return Output{Transmits: c.bind.DiscoUDP(now, src, data)}
	}
	return c.apply(now, c.dev.HandleUDP(now, c.bind.FromUDP(now, src, data), data))
}

// HandleRelay takes a datagram the relay delivered from the node with key
// from.
func (c *Core) HandleRelay(now int64, from [32]byte, data []byte) Output {
	if magic.IsDisco(data) {
		return Output{Transmits: c.bind.DiscoRelay(now, from, data)}
	}
	src, ok := c.bind.FromRelay(from, data)
	if !ok {
		return Output{}
	}
	return c.apply(now, c.dev.HandleUDP(now, src, data))
}

// HandleTUN takes a packet read from the TUN.
func (c *Core) HandleTUN(now int64, pkt []byte) Output {
	return c.apply(now, c.dev.HandleTUN(now, pkt))
}

// Tick runs the device's timers if they are due and the bind's.
func (c *Core) Tick(now int64) Output {
	var out Output
	if c.dev.NextDeadline() <= now {
		out = c.apply(now, c.dev.Tick(now))
	}
	out.Transmits = append(out.Transmits, c.bind.Tick(now)...)
	return out
}

// NextDeadline returns when Tick must run next, or device.Never.
func (c *Core) NextDeadline() int64 { return min(c.dev.NextDeadline(), c.bind.NextDeadline()) }

// Status reports how every peer is reached at now, as the control socket
// does: direct only with a confirmed address.
func (c *Core) Status(now int64) []magic.PeerStatus { return c.bind.Status(now) }

// Path returns how the peer with key is reached at now, as Status.
func (c *Core) Path(now int64, key [32]byte) magic.Path {
	for _, s := range c.bind.Status(now) {
		if s.Key == key {
			return s.Path
		}
	}
	return magic.PathNone
}

// apply routes one output of the device through the bind, as the
// runtime's loop does: a peer the device roamed to a real address goes
// back to its pseudo endpoint, with that address confirmed in the bind.
func (c *Core) apply(now int64, o device.Output) Output {
	out := Output{Packets: o.Packets, Events: o.Events}
	for _, e := range o.Events {
		if e.Kind == device.EventEndpoint && !magic.IsPseudo(e.Endpoint) {
			if pseudo, ok := c.bind.Roamed(now, e.Peer, e.Endpoint); ok {
				c.dev.SetEndpoint(e.Peer, pseudo)
			}
		}
	}
	for _, d := range o.Datagrams {
		out.Transmits = append(out.Transmits, c.bind.Route(now, d.Dst, d.Data)...)
	}
	return out
}

// applyPeers makes the peers of the device and of the bind those of the
// map: a peer the map no longer lists is removed from both, a known peer
// only gets its candidates and disco key replaced (the device keeps its
// pseudo endpoint and the bind the address the peer was last heard from;
// new candidates open a hole punching window), and a new peer is added to
// both with keepalive as its persistent keepalive.
func applyPeers(d *device.Device, b *magic.Bind, peers []coord.Node, keepalive time.Duration, logf func(string, ...any)) {
	want := make(map[[32]byte]bool, len(peers))
	for _, p := range peers {
		want[p.NodeKey] = true
	}
	for _, k := range d.Peers() {
		if !want[k] {
			d.RemovePeer(k)
			b.RemovePeer(k)
		}
	}
	for _, p := range peers {
		pc, cands := peerConfig(p)
		if b.Has(pc.PublicKey) {
			b.SetCandidates(pc.PublicKey, cands)
			b.SetDiscoKey(pc.PublicKey, p.DiscoKey)
			continue
		}
		pc.Endpoint = b.AddPeer(pc.PublicKey, cands)
		pc.PersistentKeepalive = keepalive
		b.SetDiscoKey(pc.PublicKey, p.DiscoKey)
		if err := d.AddPeer(pc); err != nil {
			b.RemovePeer(pc.PublicKey)
			logf("mesh: peer %s: %v", p.Name, err)
		}
	}
}

// Package runtime runs an internal/device on real I/O: a UDP socket, a TUN,
// the system clock and crypto/rand. One event loop owns the device and
// feeds it, one input at a time, the datagrams, the TUN packets and the
// timer that follows NextDeadline; two reader goroutines only move bytes
// from the socket and the TUN into that loop.
package runtime

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/device"
	"github.com/CesarManzoCode/malla-wg/internal/magic"
	"github.com/CesarManzoCode/malla-wg/internal/tun"
)

// maxPacket bounds one datagram or TUN packet.
const maxPacket = 65535

// queueDepth is how many inputs each reader may queue ahead of the loop.
const queueDepth = 256

// Config describes a node. Run takes ownership of Conn and TUN and closes
// both when it returns.
type Config struct {
	// Device configures the core; New replaces Rand with crypto/rand and
	// WallOffset with the wall clock at start.
	Device device.Config
	Conn   *net.UDPConn
	TUN    tun.Device
	// OnEvent, if set, is called from the event loop with every event of
	// the device, in order. It must not block.
	OnEvent func(device.Event)
	// Intercept, if set, sees every datagram before the device does and
	// reports whether it consumed it; the mesh uses it for the replies of
	// the reflexive endpoint service, which share the socket. It is called
	// from the socket's reader goroutine, must not block, and b is only
	// valid during the call.
	Intercept func(src netip.AddrPort, b []byte) bool
	// Bind, if set, sits between the device and the network: every
	// datagram goes through it both ways, and it decides per peer between
	// a UDP address and the relay. Disco datagrams, from the socket or the
	// relay, go to it and never to the device, and its timer runs in the
	// loop next to the device's. Only the event loop touches it; others
	// reach it through Query.
	Bind *magic.Bind
	// RelaySend sends a datagram through the relay to the node with the
	// given key and reports whether it was queued. It must not block.
	RelaySend func(key [32]byte, b []byte) bool
}

// Stats counts what crossed the node's socket and TUN.
type Stats struct {
	DatagramsIn, DatagramsOut uint64
	RelayIn, RelayOut         uint64 // datagrams through the relay
	PacketsIn, PacketsOut     uint64 // read from and written to the TUN
	WriteErrors               uint64
}

// Node is a running device.
type Node struct {
	dev       *device.Device
	conn      *net.UDPConn
	tun       tun.Device
	start     time.Time
	onEvent   func(device.Event)
	intercept func(netip.AddrPort, []byte) bool
	bind      *magic.Bind
	relaySend func([32]byte, []byte) bool
	queries   chan func(*device.Device)
	relayIn   chan relayed
	done      chan struct{}

	dgIn, dgOut, pktIn, pktOut, writeErrs, relayRx, relayTx atomic.Uint64
}

type relayed struct {
	src  [32]byte
	data []byte
}

type datagram struct {
	src  netip.AddrPort
	data []byte
}

// New creates the device of cfg; Run starts it.
func New(cfg Config) (*Node, error) {
	if cfg.Conn == nil || cfg.TUN == nil {
		return nil, errors.New("runtime: Config needs Conn and TUN")
	}
	start := time.Now()
	dc := cfg.Device
	dc.Rand = rand.Reader
	dc.WallOffset = start.UnixNano()
	dev, err := device.New(dc)
	if err != nil {
		return nil, err
	}
	return &Node{
		dev:       dev,
		conn:      cfg.Conn,
		tun:       cfg.TUN,
		start:     start,
		onEvent:   cfg.OnEvent,
		intercept: cfg.Intercept,
		bind:      cfg.Bind,
		relaySend: cfg.RelaySend,
		queries:   make(chan func(*device.Device)),
		relayIn:   make(chan relayed, queueDepth),
		done:      make(chan struct{}),
	}, nil
}

// PublicKey returns the node's static public key.
func (n *Node) PublicKey() [32]byte { return n.dev.PublicKey() }

// LocalAddr returns the address of the node's socket.
func (n *Node) LocalAddr() netip.AddrPort {
	return n.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// WriteTo sends b to dst from the node's socket, outside the device; the
// mesh uses it for requests that must leave from the WireGuard port.
func (n *Node) WriteTo(b []byte, dst netip.AddrPort) error {
	_, err := n.conn.WriteToUDPAddrPort(b, dst)
	return err
}

// Stats returns the node's counters.
func (n *Node) Stats() Stats {
	return Stats{
		DatagramsIn: n.dgIn.Load(), DatagramsOut: n.dgOut.Load(),
		PacketsIn: n.pktIn.Load(), PacketsOut: n.pktOut.Load(),
		WriteErrors: n.writeErrs.Load(),
		RelayIn:     n.relayRx.Load(), RelayOut: n.relayTx.Load(),
	}
}

// DeliverRelay hands the event loop a datagram that the relay delivered
// from the node with key src. It copies b, never blocks, and drops the
// datagram if the loop is behind or there is no Bind.
func (n *Node) DeliverRelay(src [32]byte, b []byte) {
	if n.bind == nil {
		return
	}
	select {
	case n.relayIn <- relayed{src: src, data: append([]byte(nil), b...)}:
	default:
	}
}

// Query runs fn on the device inside the event loop, so fn may read the
// device's state without racing with it. It fails if the node stopped.
func (n *Node) Query(ctx context.Context, fn func(*device.Device)) error {
	ran := make(chan struct{})
	select {
	case n.queries <- func(d *device.Device) { fn(d); close(ran) }:
	case <-n.done:
		return errors.New("runtime: node stopped")
	case <-ctx.Done():
		return ctx.Err()
	}
	<-ran
	return nil
}

// now is the monotonic time of the core: nanoseconds since New.
func (n *Node) now() int64 { return int64(time.Since(n.start)) }

// Now returns the monotonic time the core sees, for callers of Query that
// pass a time to the Bind.
func (n *Node) Now() int64 { return n.now() }

// Run is the event loop. It returns nil when ctx is done, or the error
// that stopped a reader; either way it closes the socket and the TUN and
// waits for the readers before returning.
func (n *Node) Run(ctx context.Context) error {
	defer close(n.done)
	ctx, cancel := context.WithCancel(ctx)
	udpIn := make(chan datagram, queueDepth)
	tunIn := make(chan []byte, queueDepth)
	errc := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); n.readUDP(ctx, udpIn, errc) }()
	go func() { defer wg.Done(); n.readTUN(ctx, tunIn, errc) }()
	defer func() {
		cancel()
		n.conn.Close()
		n.tun.Close()
		wg.Wait()
	}()

	timer := time.NewTimer(time.Hour)
	timer.Stop()
	armed := device.Never
	for {
		at := n.dev.NextDeadline()
		if n.bind != nil {
			at = min(at, n.bind.NextDeadline())
		}
		if at != armed {
			armed = at
			if at == device.Never {
				timer.Stop()
			} else {
				timer.Reset(time.Duration(max(0, at-n.now())))
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case err := <-errc:
			return err
		case d := <-udpIn:
			n.dgIn.Add(1)
			now := n.now()
			if n.bind != nil && magic.IsDisco(d.data) {
				n.transmit(n.bind.DiscoUDP(now, d.src, d.data))
				continue
			}
			src := d.src
			if n.bind != nil {
				src = n.bind.FromUDP(now, src, d.data)
			}
			n.apply(n.dev.HandleUDP(now, src, d.data))
		case r := <-n.relayIn:
			n.relayRx.Add(1)
			if magic.IsDisco(r.data) {
				n.transmit(n.bind.DiscoRelay(n.now(), r.src, r.data))
				continue
			}
			if src, ok := n.bind.FromRelay(r.src, r.data); ok {
				n.apply(n.dev.HandleUDP(n.now(), src, r.data))
			}
		case pkt := <-tunIn:
			n.pktIn.Add(1)
			n.apply(n.dev.HandleTUN(n.now(), pkt))
		case <-timer.C:
			armed = device.Never
			now := n.now()
			if n.dev.NextDeadline() <= now {
				n.apply(n.dev.Tick(now))
			}
			if n.bind != nil {
				n.transmit(n.bind.Tick(now))
			}
		case fn := <-n.queries:
			fn(n.dev)
		}
	}
}

// apply carries out one output of the device: events, then TUN packets,
// then datagrams, each in the device's order. Write errors are counted,
// not fatal: a lost datagram is what UDP allows anyway.
func (n *Node) apply(out device.Output) {
	for _, e := range out.Events {
		if n.onEvent != nil {
			n.onEvent(e)
		}
		// The device roamed a managed peer to a real address the bind did
		// not know: the bind takes it as the peer's direct address and the
		// device goes back to the pseudo endpoint.
		if n.bind != nil && e.Kind == device.EventEndpoint && !magic.IsPseudo(e.Endpoint) {
			if pseudo, ok := n.bind.Roamed(n.now(), e.Peer, e.Endpoint); ok {
				n.dev.SetEndpoint(e.Peer, pseudo)
			}
		}
	}
	for _, p := range out.Packets {
		if _, err := n.tun.Write(p); err != nil {
			n.writeErrs.Add(1)
			continue
		}
		n.pktOut.Add(1)
	}
	for _, d := range out.Datagrams {
		if n.bind == nil {
			n.writeUDP(d.Data, d.Dst)
			continue
		}
		n.transmit(n.bind.Route(n.now(), d.Dst, d.Data))
	}
}

// transmit puts what the bind decided on the network.
func (n *Node) transmit(ts []magic.Transmit) {
	for _, t := range ts {
		if !t.Relay {
			n.writeUDP(t.Data, t.Dst)
			continue
		}
		if n.relaySend == nil || !n.relaySend(t.RelayTo, t.Data) {
			n.writeErrs.Add(1)
			continue
		}
		n.relayTx.Add(1)
	}
}

func (n *Node) writeUDP(b []byte, dst netip.AddrPort) {
	if _, err := n.conn.WriteToUDPAddrPort(b, dst); err != nil {
		n.writeErrs.Add(1)
		return
	}
	n.dgOut.Add(1)
}

func (n *Node) readUDP(ctx context.Context, out chan<- datagram, errc chan<- error) {
	buf := make([]byte, maxPacket)
	for {
		k, src, err := n.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() == nil {
				errc <- fmt.Errorf("runtime: udp: %w", err)
			}
			return
		}
		// A dual-stack socket reports IPv4 peers as IPv4-mapped IPv6;
		// the core's endpoints are plain IPv4.
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		if n.intercept != nil && n.intercept(src, buf[:k]) {
			continue
		}
		select {
		case out <- datagram{src: src, data: append([]byte(nil), buf[:k]...)}:
		case <-ctx.Done():
			return
		}
	}
}

func (n *Node) readTUN(ctx context.Context, out chan<- []byte, errc chan<- error) {
	buf := make([]byte, maxPacket)
	for {
		k, err := n.tun.Read(buf)
		if err != nil {
			if ctx.Err() == nil {
				errc <- fmt.Errorf("runtime: tun: %w", err)
			}
			return
		}
		select {
		case out <- append([]byte(nil), buf[:k]...):
		case <-ctx.Done():
			return
		}
	}
}

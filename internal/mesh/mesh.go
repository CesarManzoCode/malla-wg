// Package mesh runs a node of the mesh: it registers with the
// coordination, follows the map by long-poll, reports the node's
// endpoints, and keeps the WireGuard device's peers equal to the peers of
// the map. The device's peer table is the inbound filter of the policy: a
// node the map does not list has no peer, so its handshakes fail and
// nothing from it reaches the TUN. When the coordination does not answer
// the node keeps running on the last map, cached in state_dir/netmap.json.
//
// Between the device and the network sits the bind of internal/magic:
// each peer has a direct path or goes through the relay that the map
// announces, and the device's sessions do not depend on which.
package mesh

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/coord"
	"github.com/CesarManzoCode/malla-wg/internal/device"
	"github.com/CesarManzoCode/malla-wg/internal/magic"
	"github.com/CesarManzoCode/malla-wg/internal/relay"
	"github.com/CesarManzoCode/malla-wg/internal/runtime"
	"github.com/CesarManzoCode/malla-wg/internal/tun"
	"github.com/CesarManzoCode/malla-wg/internal/x25519"
)

// DiscoKeyFile holds the node's disco private key inside state_dir.
const DiscoKeyFile = "disco.key"

// Intervals of the coordination loop.
const (
	registerTimeout  = 5 * time.Second
	pollTimeout      = coord.LongPoll + 10*time.Second
	retryDelay       = time.Second
	rediscoverEvery  = 30 * time.Second
	reflexiveTimeout = time.Second
	reflexiveTries   = 2
)

// Config describes a node. Run takes ownership of Conn and TUN.
type Config struct {
	PrivateKey [32]byte
	Name       string
	Tags       []string

	CoordURL         string
	CoordFingerprint string
	AuthKey          string
	// ReflexivePort is the UDP port of the reflexive endpoint service on
	// the coordination's host; 0 means coord.DefaultReflexivePort.
	ReflexivePort uint16
	// RelayURL is the relay used while the map announces none; the map's
	// relay wins. RelayFingerprint pins the relay's certificate; without
	// it no relay is used.
	RelayURL         string
	RelayFingerprint string

	StateDir string
	Conn     *net.UDPConn
	TUN      tun.Device
	MTU      int
	// OnEvent receives the device's events, as in runtime.Config.
	OnEvent func(device.Event)
	// Logf receives one line per coordination problem; nil discards them.
	Logf func(format string, args ...any)
}

// Node is a mesh node.
type Node struct {
	cfg       Config
	pub       [32]byte
	discoPub  [32]byte
	client    *coord.Client
	rt        *runtime.Node
	reflexive netip.AddrPort
	replies   chan reflexiveReply
	// bind is touched only inside the device's event loop (rt.Query).
	bind *magic.Bind

	// relay is the current relay client; relayRun starts the client of
	// each new relay URL. Only the coordination loop changes relayURL.
	relay    atomic.Pointer[relay.Client]
	relayRun chan *relay.Client
	relayURL string

	mu         sync.Mutex
	addr       netip.Addr
	id         uint64
	registered bool
}

type reflexiveReply struct {
	txid [12]byte
	addr netip.AddrPort
}

// New registers the node, or falls back to the cached map if the
// coordination does not answer, and builds the device with the peers it
// knows so far. It fails if there is neither a registration nor a cache.
func New(cfg Config) (*Node, error) {
	if cfg.Conn == nil || cfg.TUN == nil {
		return nil, errors.New("mesh: Config needs Conn and TUN")
	}
	if cfg.StateDir == "" {
		return nil, errors.New("mesh: state_dir is required")
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	client, err := coord.NewClient(cfg.CoordURL, cfg.CoordFingerprint)
	if err != nil {
		return nil, err
	}
	n := &Node{
		cfg:      cfg,
		pub:      x25519.PublicKey(cfg.PrivateKey),
		client:   client,
		replies:  make(chan reflexiveReply, 8),
		bind:     magic.New(),
		relayRun: make(chan *relay.Client, 1),
	}
	disco, err := loadOrCreateKey(filepath.Join(cfg.StateDir, DiscoKeyFile))
	if err != nil {
		return nil, err
	}
	n.discoPub = x25519.PublicKey(disco)
	// The bind speaks disco with this key, and the coordination publishes
	// its public half in every map (register sends discoPub).
	n.bind.SetDisco(disco, n.pub, rand.Reader)
	n.bind.SetExclude(coord.MeshPrefix)
	n.reflexive = reflexiveAddr(cfg.CoordURL, cfg.ReflexivePort)

	cache, cacheErr := coord.LoadCache(cfg.StateDir)
	if cacheErr == nil && cache.Self.NodeKey != coord.Key(n.pub) {
		cacheErr = errors.New("cache belongs to another node key")
	}
	ctx, cancel := context.WithTimeout(context.Background(), registerTimeout)
	regErr := n.register(ctx)
	cancel()
	switch {
	case regErr == nil:
	case cacheErr == nil:
		cfg.Logf("mesh: registration failed, running on the cached map: %v", regErr)
		n.addr, n.id = cache.Self.Addr, cache.Self.NodeID
	default:
		return nil, fmt.Errorf("mesh: registration failed and there is no cached map (%v): %w", cacheErr, regErr)
	}

	dc := device.Config{PrivateKey: cfg.PrivateKey, MTU: cfg.MTU}
	if cacheErr == nil {
		for _, p := range cache.Peers {
			pc, cands := peerConfig(p)
			pc.Endpoint = n.bind.AddPeer(pc.PublicKey, cands)
			n.bind.SetDiscoKey(pc.PublicKey, p.DiscoKey)
			dc.Peers = append(dc.Peers, pc)
		}
	}
	n.rt, err = runtime.New(runtime.Config{
		Device: dc, Conn: cfg.Conn, TUN: cfg.TUN, OnEvent: cfg.OnEvent, Intercept: n.intercept,
		Bind: n.bind, RelaySend: n.relaySend,
	})
	if err != nil {
		return nil, err
	}
	relayURL := cfg.RelayURL
	if cacheErr == nil && cache.Relay != "" {
		relayURL = cache.Relay
	}
	n.useRelay(relayURL)
	return n, nil
}

// relaySend is the runtime's way out through the relay.
func (n *Node) relaySend(key [32]byte, b []byte) bool {
	c := n.relay.Load()
	return c != nil && c.Send(key, b)
}

// useRelay switches to the relay at target, or to none if target is empty or
// there is no fingerprint to pin. It runs before Run or in the
// coordination loop.
func (n *Node) useRelay(target string) {
	if n.cfg.RelayFingerprint == "" {
		if target != "" && target != n.relayURL {
			n.cfg.Logf("mesh: relay %s announced but relay_fingerprint is not set; not using it", target)
		}
		n.relayURL = target
		return
	}
	if target == n.relayURL {
		return
	}
	n.relayURL = target
	var c *relay.Client
	if target != "" {
		var err error
		c, err = relay.NewClient(relay.ClientConfig{
			URL: target, Fingerprint: n.cfg.RelayFingerprint, NodeKey: n.pub,
			OnPacket: n.rt.DeliverRelay,
			OnState:  n.setRelayUp,
			Logf:     n.cfg.Logf,
		})
		if err != nil {
			n.cfg.Logf("mesh: relay: %v", err)
			c = nil
		}
	}
	// Drop a client that Run has not picked up yet.
	select {
	case <-n.relayRun:
	default:
	}
	n.relayRun <- c
}

// runRelay runs one relay client at a time, the last one useRelay chose.
// The client tells the bind when it comes up and goes down.
func (n *Node) runRelay(ctx context.Context) {
	stop := func() {}
	defer func() { stop() }()
	for {
		var c *relay.Client
		select {
		case <-ctx.Done():
			return
		case c = <-n.relayRun:
		}
		stop()
		n.relay.Store(c)
		if c == nil {
			stop = func() {}
			continue
		}
		cctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { c.Run(cctx); close(done) }()
		stop = func() { cancel(); <-done }
	}
}

// setRelayUp tells the bind whether the relay is up; it is the relay
// client's OnState, so it runs on the client's reader goroutine.
func (n *Node) setRelayUp(up bool) {
	n.rt.Query(context.Background(), func(*device.Device) { n.bind.SetRelay(up) })
}

// PublicKey returns the node's WireGuard public key.
func (n *Node) PublicKey() [32]byte { return n.pub }

// Addr returns the node's mesh address.
func (n *Node) Addr() netip.Addr {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.addr
}

// ID returns the node_id the coordination gave the node.
func (n *Node) ID() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.id
}

// Token returns the node's coordination token, "" before registering.
func (n *Node) Token() string { return n.client.Token() }

// LocalAddr returns the address of the node's socket.
func (n *Node) LocalAddr() netip.AddrPort { return n.rt.LocalAddr() }

// Stats returns the counters of the node's socket and TUN.
func (n *Node) Stats() runtime.Stats { return n.rt.Stats() }

// Peers returns the public keys of the device's peers.
func (n *Node) Peers(ctx context.Context) ([][32]byte, error) {
	var keys [][32]byte
	err := n.rt.Query(ctx, func(d *device.Device) { keys = d.Peers() })
	return keys, err
}

// Query runs fn on the device inside its event loop, as runtime.Node.Query.
func (n *Node) Query(ctx context.Context, fn func(*device.Device)) error {
	return n.rt.Query(ctx, fn)
}

// Run runs the device and the coordination loop until ctx is done or the
// device stops.
func (n *Node) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); n.coordinate(ctx) }()
	go func() { defer wg.Done(); n.runRelay(ctx) }()
	err := n.rt.Run(ctx)
	cancel()
	wg.Wait()
	return err
}

func (n *Node) isRegistered() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.registered
}

func (n *Node) register(ctx context.Context) error {
	resp, err := n.client.Register(ctx, coord.RegisterRequest{
		AuthKey: n.cfg.AuthKey, NodeKey: n.pub, DiscoKey: n.discoPub,
		Name: n.cfg.Name, Tags: n.cfg.Tags,
	})
	if err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.addr.IsValid() && n.addr != resp.Addr {
		// The TUN already carries the old address; keep it and say so.
		n.cfg.Logf("mesh: coordination moved the node from %s to %s; keeping %s", n.addr, resp.Addr, n.addr)
	} else {
		n.addr = resp.Addr
	}
	n.id, n.registered = resp.NodeID, true
	return nil
}

// coordinate is the coordination loop: register, report endpoints and
// long-poll the map, retrying every failure without ever dropping the map
// the device already has.
func (n *Node) coordinate(ctx context.Context) {
	var since uint64
	var reported []netip.AddrPort
	needReport := true
	var lastDiscover time.Time
	for ctx.Err() == nil {
		if !n.isRegistered() {
			rctx, cancel := context.WithTimeout(ctx, registerTimeout)
			err := n.register(rctx)
			cancel()
			if err != nil {
				n.cfg.Logf("mesh: register: %v", err)
				sleep(ctx, 2*retryDelay)
				continue
			}
			since, needReport = 0, true
		}
		if needReport || time.Since(lastDiscover) >= rediscoverEvery {
			eps := n.discover(ctx)
			lastDiscover = time.Now()
			if needReport || magic.EndpointsChanged(reported, eps) {
				// CallMeMaybe carries the same endpoints the map does.
				if n.rt.Query(ctx, func(*device.Device) { n.bind.SetEndpoints(eps) }) != nil {
					continue
				}
				strs := make([]string, len(eps))
				for i, ap := range eps {
					strs[i] = ap.String()
				}
				rctx, cancel := context.WithTimeout(ctx, registerTimeout)
				err := n.client.ReportEndpoints(rctx, strs)
				cancel()
				if err != nil {
					n.coordFailed(ctx, "report endpoints", err)
					continue
				}
				reported, needReport = eps, false
			}
		}
		pctx, cancel := context.WithTimeout(ctx, pollTimeout)
		nm, raw, err := n.client.Netmap(pctx, since)
		cancel()
		if err != nil {
			n.coordFailed(ctx, "netmap", err)
			continue
		}
		since = nm.Version
		n.apply(ctx, nm, raw)
	}
}

// coordFailed logs a failed call and waits before the next one. A 401
// means the token is no longer valid (revoked, or the coordination lost
// its state), so the next turn registers again.
func (n *Node) coordFailed(ctx context.Context, what string, err error) {
	if ctx.Err() != nil {
		return
	}
	if !errors.Is(err, context.Canceled) {
		n.cfg.Logf("mesh: %s: %v", what, err)
	}
	if coord.IsStatus(err, 401) {
		n.mu.Lock()
		n.registered = false
		n.mu.Unlock()
	}
	sleep(ctx, retryDelay)
}

// apply makes the device's peers those of nm, then caches nm. The device
// goes first so that a cache without a peer means the device has already
// forgotten it.
func (n *Node) apply(ctx context.Context, nm coord.Netmap, raw []byte) {
	if nm.Self.NodeKey != coord.Key(n.pub) {
		n.cfg.Logf("mesh: netmap for another node key; ignored")
		return
	}
	err := n.rt.Query(ctx, func(d *device.Device) {
		want := make(map[[32]byte]bool, len(nm.Peers))
		for _, p := range nm.Peers {
			want[p.NodeKey] = true
		}
		for _, k := range d.Peers() {
			if !want[k] {
				d.RemovePeer(k)
				n.bind.RemovePeer(k)
			}
		}
		for _, p := range nm.Peers {
			pc, cands := peerConfig(p)
			if n.bind.Has(pc.PublicKey) {
				// The device keeps its pseudo endpoint; only the
				// candidates change, and the address the peer was last
				// heard from stays. New candidates open a hole
				// punching window.
				n.bind.SetCandidates(pc.PublicKey, cands)
				n.bind.SetDiscoKey(pc.PublicKey, p.DiscoKey)
				continue
			}
			pc.Endpoint = n.bind.AddPeer(pc.PublicKey, cands)
			n.bind.SetDiscoKey(pc.PublicKey, p.DiscoKey)
			if err := d.AddPeer(pc); err != nil {
				n.bind.RemovePeer(pc.PublicKey)
				n.cfg.Logf("mesh: peer %s: %v", p.Name, err)
			}
		}
	})
	if err != nil {
		return
	}
	relayURL := nm.Relay
	if relayURL == "" {
		relayURL = n.cfg.RelayURL
	}
	n.useRelay(relayURL)
	if err := coord.SaveCache(n.cfg.StateDir, raw); err != nil {
		n.cfg.Logf("mesh: cache: %v", err)
	}
}

// peerConfig turns a peer of the map into a device peer, its key and its
// address as the only allowed IP, and returns the endpoints that parse as
// the bind's direct candidates. The device's endpoint is left for the
// bind's pseudo endpoint.
func peerConfig(p coord.Node) (device.PeerConfig, []netip.AddrPort) {
	pc := device.PeerConfig{PublicKey: p.NodeKey}
	if p.Addr.IsValid() {
		pc.AllowedIPs = []netip.Prefix{netip.PrefixFrom(p.Addr, p.Addr.BitLen())}
	}
	var cands []netip.AddrPort
	for _, e := range p.Endpoints {
		// An address of the mesh would send the tunnel through itself.
		if ap, err := netip.ParseAddrPort(e); err == nil && !coord.MeshPrefix.Contains(ap.Addr().Unmap()) {
			cands = append(cands, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
		}
	}
	return pc, cands
}

// PeerPath returns how the peer with key is reached now: direct with its
// address, relay, or none.
func (n *Node) PeerPath(ctx context.Context, key [32]byte) (magic.Path, netip.AddrPort, error) {
	var path magic.Path
	var ep netip.AddrPort
	err := n.rt.Query(ctx, func(*device.Device) { path, ep = n.bind.PathOf(n.rt.Now(), key) })
	return path, ep, err
}

// discover returns the node's endpoints (magic.Endpoints): the reflexive
// one first, then the local ones with the socket's port.
func (n *Node) discover(ctx context.Context) []netip.AddrPort {
	reflexive, _ := n.queryReflexive(ctx)
	local := n.rt.LocalAddr()
	return magic.Endpoints(reflexive, localAddrs(local), local.Port(), coord.MeshPrefix)
}

// queryReflexive asks the reflexive service, from the WireGuard socket,
// for the address it sees.
func (n *Node) queryReflexive(ctx context.Context) (netip.AddrPort, bool) {
	if !n.reflexive.IsValid() {
		return netip.AddrPort{}, false
	}
	for range reflexiveTries {
		var txid [12]byte
		if _, err := rand.Read(txid[:]); err != nil {
			return netip.AddrPort{}, false
		}
		if err := n.rt.WriteTo(coord.ReflexiveRequest(txid), n.reflexive); err != nil {
			n.cfg.Logf("mesh: reflexive request: %v", err)
			return netip.AddrPort{}, false
		}
		timeout := time.NewTimer(reflexiveTimeout)
	wait:
		for {
			select {
			case r := <-n.replies:
				if r.txid == txid {
					timeout.Stop()
					return r.addr, true
				}
			case <-timeout.C:
				break wait
			case <-ctx.Done():
				timeout.Stop()
				return netip.AddrPort{}, false
			}
		}
	}
	return netip.AddrPort{}, false
}

// intercept takes the reflexive replies off the WireGuard socket.
func (n *Node) intercept(_ netip.AddrPort, b []byte) bool {
	if !coord.IsReflexive(b) {
		return false
	}
	if txid, addr, ok := coord.ParseReflexiveReply(b); ok {
		select {
		case n.replies <- reflexiveReply{txid: txid, addr: addr}:
		default:
		}
	}
	return true
}

// localAddrs returns the socket's address if it is bound to one, or else
// the IPv4 addresses of the host's interfaces that are up, without
// loopback and without the mesh's own addresses (the TUN).
func localAddrs(local netip.AddrPort) []netip.Addr {
	if a := local.Addr().Unmap(); !a.IsUnspecified() {
		return []netip.Addr{a}
	}
	var eps []netip.Addr
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			pfx, err := netip.ParsePrefix(a.String())
			if err != nil || !pfx.Addr().Is4() || coord.MeshPrefix.Contains(pfx.Addr()) {
				continue
			}
			eps = append(eps, pfx.Addr())
		}
	}
	return eps
}

// reflexiveAddr is the reflexive service on the coordination's host. A
// host name is resolved once, at start.
func reflexiveAddr(coordURL string, port uint16) netip.AddrPort {
	if port == 0 {
		port = coord.DefaultReflexivePort
	}
	u, err := url.Parse(coordURL)
	if err != nil {
		return netip.AddrPort{}
	}
	host := u.Hostname()
	if a, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(a.Unmap(), port)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return netip.AddrPort{}
	}
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok && a.Unmap().Is4() {
			return netip.AddrPortFrom(a.Unmap(), port)
		}
	}
	return netip.AddrPort{}
}

// loadOrCreateKey reads a base64 private key, or creates one.
func loadOrCreateKey(path string) ([32]byte, error) {
	var k [32]byte
	b, err := os.ReadFile(path)
	if err == nil {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(raw) != len(k) {
			return k, fmt.Errorf("mesh: %s is not a base64 key of 32 bytes", path)
		}
		copy(k[:], raw)
		return k, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return k, err
	}
	if _, err := rand.Read(k[:]); err != nil {
		return k, err
	}
	return k, os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(k[:])+"\n"), 0o600)
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// Package mesh runs a node of the mesh: it registers with the
// coordination, follows the map by long-poll, reports the node's
// endpoints, and keeps the WireGuard device's peers equal to the peers of
// the map. The device's peer table is the inbound filter of the policy: a
// node the map does not list has no peer, so its handshakes fail and
// nothing from it reaches the TUN. When the coordination does not answer
// the node keeps running on the last map, cached in state_dir/netmap.json.
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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/coord"
	"github.com/CesarManzoCode/malla-wg/internal/device"
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

	mu         sync.Mutex
	addr       netip.Addr
	id         uint64
	registered bool

	// mapEndpoint is the endpoint the map last gave each peer; the device
	// gets a new one only when the map's changes, so roaming is not undone
	// by every map. Only the coordination loop touches it.
	mapEndpoint map[[32]byte]netip.AddrPort
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
		cfg:         cfg,
		pub:         x25519.PublicKey(cfg.PrivateKey),
		client:      client,
		replies:     make(chan reflexiveReply, 8),
		mapEndpoint: make(map[[32]byte]netip.AddrPort),
	}
	disco, err := loadOrCreateKey(filepath.Join(cfg.StateDir, DiscoKeyFile))
	if err != nil {
		return nil, err
	}
	n.discoPub = x25519.PublicKey(disco)
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
			pc, ep := peerConfig(p)
			dc.Peers = append(dc.Peers, pc)
			n.mapEndpoint[pc.PublicKey] = ep
		}
	}
	n.rt, err = runtime.New(runtime.Config{Device: dc, Conn: cfg.Conn, TUN: cfg.TUN, OnEvent: cfg.OnEvent, Intercept: n.intercept})
	if err != nil {
		return nil, err
	}
	return n, nil
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
	wg.Add(1)
	go func() { defer wg.Done(); n.coordinate(ctx) }()
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
	var reported []string
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
			if needReport || !slices.Equal(eps, reported) {
				rctx, cancel := context.WithTimeout(ctx, registerTimeout)
				err := n.client.ReportEndpoints(rctx, eps)
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
				delete(n.mapEndpoint, k)
			}
		}
		for _, p := range nm.Peers {
			pc, ep := peerConfig(p)
			old, known := n.mapEndpoint[pc.PublicKey]
			switch {
			case !known:
				if err := d.AddPeer(pc); err != nil {
					n.cfg.Logf("mesh: peer %s: %v", p.Name, err)
					continue
				}
			case ep.IsValid() && ep != old:
				d.SetEndpoint(pc.PublicKey, ep)
			}
			n.mapEndpoint[pc.PublicKey] = ep
		}
	})
	if err != nil {
		return
	}
	if err := coord.SaveCache(n.cfg.StateDir, raw); err != nil {
		n.cfg.Logf("mesh: cache: %v", err)
	}
}

// peerConfig turns a peer of the map into a device peer: its key, its
// address as the only allowed IP, and its first endpoint that parses.
func peerConfig(p coord.Node) (device.PeerConfig, netip.AddrPort) {
	pc := device.PeerConfig{PublicKey: p.NodeKey}
	if p.Addr.IsValid() {
		pc.AllowedIPs = []netip.Prefix{netip.PrefixFrom(p.Addr, p.Addr.BitLen())}
	}
	for _, e := range p.Endpoints {
		if ap, err := netip.ParseAddrPort(e); err == nil {
			pc.Endpoint = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
			break
		}
	}
	return pc, pc.Endpoint
}

// discover returns the node's endpoints: the reflexive one first, then the
// local ones, without repeats.
func (n *Node) discover(ctx context.Context) []string {
	var eps []string
	add := func(ap netip.AddrPort) {
		if s := ap.String(); ap.IsValid() && !slices.Contains(eps, s) {
			eps = append(eps, s)
		}
	}
	if ap, ok := n.queryReflexive(ctx); ok {
		add(ap)
	}
	for _, ap := range localEndpoints(n.rt.LocalAddr()) {
		add(ap)
	}
	return eps
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

// localEndpoints returns the socket's address if it is bound to one, or
// else the addresses of the host's interfaces that are up, without
// loopback, with the socket's port.
func localEndpoints(local netip.AddrPort) []netip.AddrPort {
	if a := local.Addr().Unmap(); !a.IsUnspecified() {
		return []netip.AddrPort{netip.AddrPortFrom(a, local.Port())}
	}
	var eps []netip.AddrPort
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
			if err != nil || !pfx.Addr().Is4() {
				continue
			}
			eps = append(eps, netip.AddrPortFrom(pfx.Addr(), local.Port()))
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

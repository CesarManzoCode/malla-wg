package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/coord"
	"github.com/CesarManzoCode/malla-wg/internal/device"
	"github.com/CesarManzoCode/malla-wg/internal/mesh"
	"github.com/CesarManzoCode/malla-wg/internal/runtime"
	"github.com/CesarManzoCode/malla-wg/internal/tun"
	"github.com/CesarManzoCode/malla-wg/internal/x25519"
	"github.com/CesarManzoCode/malla-wg/sim"
)

// These tests need no privilege: UDP on 127.0.0.1, in-memory TUNs and the
// coordination on a local port.

const (
	testAuthKey = "e2e-auth"
	testAdmin   = "e2e-admin"
)

// TestCritPolicyUnauthorized is criterion 22: the policy allows only A↔B.
// C is registered too, knows B's public key and configures B as a static
// peer, but nothing it sends reaches B, because B has no peer for C;
// traffic between A and B does arrive.
func TestCritPolicyUnauthorized(t *testing.T) {
	co := startCoord(t, &coord.Policy{Rules: []coord.Rule{{Src: []string{"a"}, Dst: []string{"b"}}}})
	a := startMeshNode(t, co, "a")
	b := startMeshNode(t, co, "b")
	waitPeers(t, a, b)
	waitPeers(t, b, a)
	mustDeliver(t, a, b, "a to b")
	mustDeliver(t, b, a, "b to a")

	// C registers like any node, but runs a plain device with B as a
	// static peer instead of following its map.
	var cPriv [32]byte
	rand.Read(cPriv[:])
	cl, err := coord.NewClient(co.url, co.fp)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reg, err := cl.Register(ctx, coord.RegisterRequest{AuthKey: testAuthKey, NodeKey: x25519.PublicKey(cPriv), Name: "c"})
	if err != nil {
		t.Fatal(err)
	}
	nm, _, err := cl.Netmap(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(nm.Peers) != 0 {
		t.Fatalf("map of c lists %d peers, want none", len(nm.Peers))
	}
	c := startStaticNode(t, cPriv, reg.Addr, device.PeerConfig{
		PublicKey:  b.node.PublicKey(),
		AllowedIPs: []netip.Prefix{netip.PrefixFrom(b.node.Addr(), 32)},
		Endpoint:   b.node.LocalAddr(),
	})
	// Give b's map time to settle after c registered, then check it.
	time.Sleep(time.Second)
	if hasPeer(t, b, x25519.PublicKey(cPriv)) {
		t.Fatal("b has c among its peers")
	}
	never(t, 3*time.Second, func(i int) {
		c.send(b.node.Addr(), fmt.Sprintf("c to b %d", i))
	}, b, "c to b")
	mustDeliver(t, a, b, "a to b again")
}

// TestCritRevocation is criterion 23: with A↔B flowing the admin revokes
// B; A's map, both the raw /v1/netmap answer and its cache on disk, stops
// listing B's key, A's traffic to B stops arriving, and registering B's
// key again is refused.
func TestCritRevocation(t *testing.T) {
	co := startCoord(t, &coord.Policy{Rules: []coord.Rule{{Src: []string{"a"}, Dst: []string{"b"}}}})
	a := startMeshNode(t, co, "a")
	b := startMeshNode(t, co, "b")
	waitPeers(t, a, b)
	waitPeers(t, b, a)
	mustDeliver(t, a, b, "a to b")

	bKey := b.node.PublicKey()
	bKey64 := base64.StdEncoding.EncodeToString(bKey[:])
	co.admin(t, "POST", "/v1/admin/revoke", fmt.Sprintf(`{"node_id":%d}`, b.node.ID()))

	raw := co.rawNetmap(t, a.node.Token())
	if bytes.Contains(raw, []byte(bKey64)) {
		t.Fatalf("raw netmap of a still lists b's key:\n%s", raw)
	}
	cache := filepath.Join(a.stateDir, coord.CacheFile)
	if !meshWait(10*time.Second, func() bool {
		b, err := os.ReadFile(cache)
		return err == nil && !bytes.Contains(b, []byte(bKey64)) && !hasPeer(t, a, bKey)
	}) {
		got, _ := os.ReadFile(cache)
		t.Fatalf("a's cache or device still has b after 10 s:\n%s", got)
	}
	never(t, 3*time.Second, func(i int) {
		a.send(b.node.Addr(), fmt.Sprintf("a to b after revoke %d", i))
	}, b, "a to b after revoke")

	cl, err := coord.NewClient(co.url, co.fp)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = cl.Register(ctx, coord.RegisterRequest{AuthKey: testAuthKey, NodeKey: bKey, Name: "b-again"})
	if !coord.IsStatus(err, http.StatusForbidden) {
		t.Fatalf("registering b's revoked key: %v, want status 403", err)
	}
}

// TestCritCoordDown is criterion 24: with A↔B flowing the coordination
// stops, and for 10 s more every datagram sent between A and B arrives.
func TestCritCoordDown(t *testing.T) {
	co := startCoord(t, &coord.Policy{Rules: []coord.Rule{{Src: []string{"a"}, Dst: []string{"b"}}}})
	a := startMeshNode(t, co, "a")
	b := startMeshNode(t, co, "b")
	waitPeers(t, a, b)
	waitPeers(t, b, a)
	mustDeliver(t, a, b, "a to b")
	mustDeliver(t, b, a, "b to a")

	co.stop()
	sent := 0
	start := time.Now()
	for time.Since(start) < 10*time.Second {
		for _, dir := range [][2]*meshNode{{a, b}, {b, a}} {
			msg := fmt.Sprintf("coord down %d %s", sent, dir[0].name)
			want := dir[0].send(dir[1].node.Addr(), msg)
			if !receive(dir[1], want, time.Second) {
				t.Fatalf("datagram %q sent %v after the coordination stopped did not arrive", msg, time.Since(start))
			}
		}
		sent++
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("%d datagrams each way arrived with the coordination down", sent)
}

// testCoord is a coordination server with its reflexive service.
type testCoord struct {
	url, fp  string
	stunPort uint16
	stop     func()
}

func startCoord(t *testing.T, policy *coord.Policy) *testCoord {
	t.Helper()
	srv, err := coord.NewServer(coord.ServerConfig{
		StateDir: t.TempDir(), AdminToken: testAdmin, AuthKeys: []string{testAuthKey},
		Policy: policy, Logf: safeLogf(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx, ln); close(done) }()
	go coord.ServeReflexive(uc)
	var once sync.Once
	co := &testCoord{
		url:      "https://" + ln.Addr().String(),
		fp:       srv.Fingerprint(),
		stunPort: uint16(uc.LocalAddr().(*net.UDPAddr).Port),
		stop:     func() { once.Do(func() { cancel(); uc.Close(); <-done }) },
	}
	t.Cleanup(co.stop)
	return co
}

func (co *testCoord) httpClient(t *testing.T) *http.Client {
	tc, err := coord.PinnedTLSConfig(co.fp)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}
}

func (co *testCoord) call(t *testing.T, method, path, token, body string) []byte {
	t.Helper()
	req, err := http.NewRequest(method, co.url+path, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := co.httpClient(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, b)
	}
	return b
}

func (co *testCoord) admin(t *testing.T, method, path, body string) {
	t.Helper()
	co.call(t, method, path, testAdmin, body)
}

// rawNetmap is the body of GET /v1/netmap?since=0, which answers at once.
func (co *testCoord) rawNetmap(t *testing.T, token string) []byte {
	t.Helper()
	return co.call(t, "GET", "/v1/netmap?since=0", token, "")
}

// meshNode is a mesh.Node on an in-memory TUN.
type meshNode struct {
	name     string
	node     *mesh.Node
	tun      *tun.Mem
	stateDir string
}

func startMeshNode(t *testing.T, co *testCoord, name string) *meshNode {
	t.Helper()
	var priv [32]byte
	rand.Read(priv[:])
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	mt := tun.NewMem(name, 256)
	n := &meshNode{name: name, tun: mt, stateDir: t.TempDir()}
	n.node, err = mesh.New(mesh.Config{
		PrivateKey: priv, Name: name,
		CoordURL: co.url, CoordFingerprint: co.fp, AuthKey: testAuthKey, ReflexivePort: co.stunPort,
		StateDir: n.stateDir, Conn: conn, TUN: mt, Logf: safeLogf(t),
	})
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	runInBackground(t, n.node.Run)
	return n
}

func (n *meshNode) send(dst netip.Addr, msg string) []byte {
	pkt := sim.IPv4Packet(n.node.Addr(), dst, []byte(msg))
	n.tun.Inject(pkt)
	return pkt
}

// staticNode is a plain device with fixed peers, outside the mesh.
type staticNode struct {
	addr netip.Addr
	tun  *tun.Mem
}

func startStaticNode(t *testing.T, priv [32]byte, addr netip.Addr, peers ...device.PeerConfig) *staticNode {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	mt := tun.NewMem("static", 256)
	rt, err := runtime.New(runtime.Config{Device: device.Config{PrivateKey: priv, Peers: peers}, Conn: conn, TUN: mt})
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	runInBackground(t, rt.Run)
	return &staticNode{addr: addr, tun: mt}
}

func (n *staticNode) send(dst netip.Addr, msg string) []byte {
	pkt := sim.IPv4Packet(n.addr, dst, []byte(msg))
	n.tun.Inject(pkt)
	return pkt
}

// runInBackground runs fn until the test ends and waits for it to return.
func runInBackground(t *testing.T, fn func(context.Context) error) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { fn(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

// safeLogf logs through t until the test ends and drops lines after.
func safeLogf(t *testing.T) func(string, ...any) {
	var mu sync.Mutex
	over := false
	t.Cleanup(func() { mu.Lock(); over = true; mu.Unlock() })
	return func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if !over {
			t.Logf(format, args...)
		}
	}
}

func hasPeer(t *testing.T, n *meshNode, key [32]byte) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	keys, err := n.node.Peers(ctx)
	if err != nil {
		t.Errorf("%s: peers: %v", n.name, err)
		return false
	}
	return slices.Contains(keys, key)
}

// waitPeers waits until n has p as a peer.
func waitPeers(t *testing.T, n, p *meshNode) {
	t.Helper()
	if !meshWait(10*time.Second, func() bool { return hasPeer(t, n, p.node.PublicKey()) }) {
		t.Fatalf("%s did not get %s from the map in 10 s", n.name, p.name)
	}
}

// mustDeliver sends from one node to the other, again every 200 ms while
// the handshake and the endpoints settle, until a copy arrives.
func mustDeliver(t *testing.T, from, to *meshNode, msg string) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); {
		if receive(to, from.send(to.node.Addr(), msg), 200*time.Millisecond) {
			return
		}
	}
	t.Fatalf("%q from %s never reached %s in 10 s", msg, from.name, to.name)
}

// receive waits up to d for want on n's TUN, skipping other packets.
func receive(n *meshNode, want []byte, d time.Duration) bool {
	timeout := time.NewTimer(d)
	defer timeout.Stop()
	for {
		select {
		case got := <-n.tun.Outbound():
			if bytes.Equal(got, want) {
				return true
			}
		case <-timeout.C:
			return false
		}
	}
}

// never sends a packet every 100 ms for d and fails if any packet whose
// payload starts with prefix comes out of to's TUN.
func never(t *testing.T, d time.Duration, send func(i int), to *meshNode, prefix string) {
	t.Helper()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	end := time.After(d)
	for i := 0; ; i++ {
		send(i)
		select {
		case got := <-to.tun.Outbound():
			if len(got) >= 20 && bytes.HasPrefix(got[20:], []byte(prefix)) {
				t.Fatalf("%q reached %s", got[20:], to.name)
			}
		case <-tick.C:
		case <-end:
			return
		}
	}
}

func meshWait(d time.Duration, cond func() bool) bool {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return cond()
}

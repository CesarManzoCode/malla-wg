//go:build linux

package matrix

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/CesarManzoCode/malla-wg/verify/netns"
)

// Real NATs (contract §4.4). The "internet" namespace holds, on its
// loopback, the coordination with its reflexive service and the relay on
// svcAddr and the probe servers on their own addresses; every top-level
// NAT or public host hangs from it on its own /24 of 198.18.0.0/15.
var (
	svcAddr    = netip.MustParseAddr("198.51.100.1")
	probeIP1   = netip.MustParseAddr("198.51.100.10")
	probeIP2   = netip.MustParseAddr("198.51.100.11")
	probeOther = netip.MustParseAddr("198.51.100.12") // never contacted
)

const (
	linuxParallel = 4    // cells at once (contract §6)
	probeOffset   = 1000 // a host probes from its mesh port + 1000
	eimFirstPort  = 40000
	probeWait     = time.Second
)

// endpoint is an inside UDP endpoint of a NAT.
type endpoint struct {
	addr netip.Addr
	port uint16
}

// natBox is one NAT router. With EIM the i-th endpoint of below is mapped
// to eimFirstPort+i, a fixed port per inside endpoint; any other source
// keeps its port if it can (snat without a port).
type natBox struct {
	ns, typ string
	hairpin bool
	ext     netip.Addr
	below   []endpoint
}

// outside returns the endpoints the box presents for below: with EIM the
// fixed ones, with APDM none, since its ports are random.
func (n *natBox) outside() []endpoint {
	if m, _ := behaviors(n.typ); m != "EIM" {
		return nil
	}
	var out []endpoint
	for i := range n.below {
		out = append(out, endpoint{n.ext, uint16(eimFirstPort + i)})
	}
	return out
}

// rules is the nftables ruleset of the box. "wan" is its outside
// interface, every other one is inside. Mapping: EIM is snat to a fixed
// port per inside endpoint, APDM snat fully-random to the external
// address. Filtering: @fc maps an external port to its inside endpoint
// and @seen holds the addresses each external port sent to; EIF lets in
// everything to a known port, ADF only from an address in @seen, APDF
// only conntrack replies. Unsolicited UDP to the router itself is dropped
// before conntrack confirms it, so it leaves no entry that would collide
// with a later mapping. With hairpin, a datagram from inside to the
// external address is translated out and then in: dnat by @fc in
// prerouting, snat by the mapping chain in postrouting, and the filter of
// the destination mapping, which needs the translated source, is checked
// after snat with @seenhp (ports that sent to the external address) and
// @seenhpp (port pairs).
func (n *natBox) rules() string {
	m, f := behaviors(n.typ)
	ext := n.ext.String()
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, "\t\t"+format+"\n", args...) }
	b.WriteString(`table ip malla {
	map fc { type inet_service : ipv4_addr . inet_service; flags dynamic, timeout; timeout 120s; }
	set seen { type inet_service . ipv4_addr; flags dynamic, timeout; timeout 120s; }
	set seenhp { type inet_service; flags dynamic, timeout; timeout 120s; }
	set seenhpp { type inet_service . inet_service; flags dynamic, timeout; timeout 120s; }
	chain pre {
		type nat hook prerouting priority dstnat; policy accept;
`)
	switch f {
	case "EIF":
		w(`meta l4proto udp iifname "wan" ip daddr %s dnat ip to udp dport map @fc`, ext)
	case "ADF":
		w(`meta l4proto udp iifname "wan" ip daddr %s udp dport . ip saddr @seen dnat ip to udp dport map @fc`, ext)
	}
	if n.hairpin {
		w(`meta l4proto udp iifname != "wan" ip daddr %s dnat ip to udp dport map @fc`, ext)
	}
	b.WriteString(`	}
	chain post {
		type nat hook postrouting priority srcnat; policy accept;
		iifname "wan" return
		oifname "wan" jump mapping
		ct status dnat jump mapping
	}
	chain mapping {
`)
	if m == "EIM" {
		for i, e := range n.below {
			w(`ip saddr %s udp sport %d snat ip to %s:%d`, e.addr, e.port, ext, eimFirstPort+i)
		}
		w(`snat ip to %s`, ext)
	} else {
		w(`snat ip to %s fully-random`, ext)
	}
	b.WriteString(`	}
	chain track {
		type filter hook postrouting priority srcnat + 1; policy accept;
`)
	const out, hp = `meta l4proto udp oifname "wan"`, `meta l4proto udp iifname != "wan" oifname != "wan"`
	w(`%s ct direction original ct status snat update @fc { ct reply proto-dst : ct original ip saddr . ct original proto-src }`, out)
	w(`%s ct direction original ct status snat update @seen { ct reply proto-dst . ip daddr }`, out)
	w(`%s ct direction reply ct status dnat update @seen { ct original proto-dst . ip daddr }`, out)
	if n.hairpin {
		w(`%s ct direction original update @fc { ct reply proto-dst : ct original ip saddr . ct original proto-src }`, hp)
		w(`%s ct direction original update @seenhp { ct reply proto-dst }`, hp)
		w(`%s ct direction original update @seenhpp { ct reply proto-dst . ct original proto-dst }`, hp)
		w(`%s ct direction reply update @seenhp { ct original proto-dst }`, hp)
		w(`%s ct direction reply update @seenhpp { ct original proto-dst . ct reply proto-dst }`, hp)
		switch f {
		case "ADF":
			w(`%s ct direction original ct state new ct original proto-dst != @seenhp drop`, hp)
		case "APDF":
			w(`%s ct direction original ct state new ct original proto-dst . ct reply proto-dst != @seenhpp drop`, hp)
		}
	}
	b.WriteString(`	}
	chain fwd {
		type filter hook forward priority filter; policy accept;
		iifname != "wan" oifname != "wan" ct status dnat accept
		iifname != "wan" oifname != "wan" drop
	}
	chain in {
		type filter hook input priority filter; policy accept;
		meta l4proto udp drop
	}
}
`)
	return b.String()
}

// lhost is a mesh host of a topology: its namespace, address and mesh
// port, and the type of NAT it sits behind (composed for a CGNAT, "none"
// if public).
type lhost struct {
	ns   string
	addr netip.Addr
	port uint16
	typ  string
}

func (h lhost) endpoints() []endpoint {
	return []endpoint{{h.addr, h.port}, {h.addr, h.port + probeOffset}}
}

func (h lhost) probeLocal() netip.AddrPort { return netip.AddrPortFrom(h.addr, h.port+probeOffset) }

// topo is the real topology of one cell. With shared, a and b sit behind
// one NAT (or one CGNAT) of type sharedTyp and external address
// sharedExt, which has hairpin or not.
type topo struct {
	t         testing.TB
	dir, pre  string
	inet      string
	links     int
	a, b      lhost
	shared    bool
	hairpin   bool
	sharedTyp string
	sharedExt netip.Addr
}

// buildTopo builds the cell's topology of §4.1 with namespaces named after
// slot, like newWorld does in the simulator: pair puts each host behind its
// own NAT or on the internet, hairpin both behind one NAT in two inside
// segments, cgnat a behind a home NAT inside a CGNAT and b as in pair, and
// cgnat_same each behind its home NAT, both inside one CGNAT.
func buildTopo(t testing.TB, slot int, group, cell string) *topo {
	t.Helper()
	tp := &topo{t: t, dir: t.TempDir(), pre: fmt.Sprintf("m%d", slot)}
	tp.inet = tp.newNS("I")
	for _, a := range []netip.Addr{svcAddr, probeIP1, probeIP2, probeOther} {
		netns.MustExec(t, tp.inet, "ip", "addr", "add", a.String()+"/32", "dev", "lo")
	}
	left, right, _ := strings.Cut(cell, "|")
	hp := right == "hairpin=True"
	tp.a = lhost{ns: tp.newNS("A"), port: 51820}
	tp.b = lhost{ns: tp.newNS("B"), port: 51821}
	switch group {
	case "pair":
		tp.side(&tp.a, left, 1)
		tp.side(&tp.b, right, 2)
	case "hairpin":
		r := tp.newNS("N")
		ext := tp.attach(r, "wan")
		tp.a.addr = tp.inside(r, 1, tp.a.ns, "eth0", "192.168.1")
		tp.b.addr = tp.inside(r, 2, tp.b.ns, "eth0", "192.168.2")
		tp.load(&natBox{ns: r, typ: left, hairpin: hp, ext: ext, below: append(tp.a.endpoints(), tp.b.endpoints()...)})
		tp.a.typ, tp.b.typ = left, left
		tp.shared, tp.hairpin, tp.sharedTyp, tp.sharedExt = true, hp, left, ext
	case "cgnat", "cgnat_same":
		h, c, _ := strings.Cut(left, ">")
		cg := tp.newNS("C")
		ext := tp.attach(cg, "wan")
		home := func(hs *lhost, k int) []endpoint {
			r := tp.newNS(fmt.Sprintf("H%d", k))
			hext := tp.inside(cg, k, r, "wan", fmt.Sprintf("100.64.%d", k))
			hs.addr = tp.inside(r, 1, hs.ns, "eth0", fmt.Sprintf("192.168.%d", k))
			box := &natBox{ns: r, typ: h, ext: hext, below: hs.endpoints()}
			tp.load(box)
			hs.typ = composed(h, c)
			return box.outside()
		}
		below := home(&tp.a, 1)
		same := group == "cgnat_same"
		if same {
			below = append(below, home(&tp.b, 2)...)
			tp.shared, tp.hairpin, tp.sharedTyp, tp.sharedExt = true, hp, composed(h, c), ext
		}
		tp.load(&natBox{ns: cg, typ: c, hairpin: same && hp, ext: ext, below: below})
		if !same {
			tp.side(&tp.b, right, 2)
		}
	default:
		t.Fatalf("unknown group %q", group)
	}
	return tp
}

// newNS adds namespace pre+name, which forwards and has no reverse path
// filter.
func (tp *topo) newNS(name string) string {
	ns := tp.pre + name
	netns.Add(tp.t, ns)
	netns.MustExec(tp.t, ns, "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward && "+
		"echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter && echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter")
	return ns
}

// attach joins ns to the internet on a /24 of its own, routes ns's default
// through it and returns ns's address there.
func (tp *topo) attach(ns, ifname string) netip.Addr {
	tp.links++
	base := fmt.Sprintf("198.18.%d", tp.links)
	netns.Veth(tp.t, tp.inet, fmt.Sprintf("x%d", tp.links), base+".1/24", ns, ifname, base+".2/24")
	netns.MustExec(tp.t, ns, "ip", "route", "add", "default", "via", base+".1")
	return netip.MustParseAddr(base + ".2")
}

// inside joins ns to router's inside interface in<idx> on base.0/24,
// routes ns's default through the router and returns ns's address.
func (tp *topo) inside(router string, idx int, ns, ifname, base string) netip.Addr {
	netns.Veth(tp.t, router, fmt.Sprintf("in%d", idx), base+".1/24", ns, ifname, base+".2/24")
	netns.MustExec(tp.t, ns, "ip", "route", "add", "default", "via", base+".1")
	return netip.MustParseAddr(base + ".2")
}

// side puts h behind its own NAT of type typ on segment 192.168.k.0/24,
// or on the internet for none.
func (tp *topo) side(h *lhost, typ string, k int) {
	h.typ = typ
	if typ == "none" {
		h.addr = tp.attach(h.ns, "eth0")
		return
	}
	r := tp.newNS(fmt.Sprintf("N%d", k))
	ext := tp.attach(r, "wan")
	h.addr = tp.inside(r, 1, h.ns, "eth0", fmt.Sprintf("192.168.%d", k))
	tp.load(&natBox{ns: r, typ: typ, ext: ext, below: h.endpoints()})
}

func (tp *topo) load(n *natBox) {
	path := filepath.Join(tp.dir, n.ns+".nft")
	writeFile(tp.t, path, n.rules())
	netns.MustExec(tp.t, n.ns, "nft", "-f", path)
}

// Fidelity probe (contract §4.4): the probe servers live in the internet
// namespace; s1 and s3 share an address, s2 has another, other is an
// address never contacted and port2 is s1's address on a port never
// contacted.
type probeServers struct {
	s1, s2, s3, other, port2 *net.UDPConn
}

func listenIn(ns string, ap netip.AddrPort) (*net.UDPConn, error) {
	var c *net.UDPConn
	err := netns.Do(ns, func() (err error) {
		c, err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(ap))
		return err
	})
	return c, err
}

func (tp *topo) servers() (*probeServers, error) {
	s := &probeServers{}
	for _, p := range []struct {
		c  **net.UDPConn
		ap netip.AddrPort
	}{
		{&s.s1, netip.AddrPortFrom(probeIP1, 3478)}, {&s.s2, netip.AddrPortFrom(probeIP2, 3479)},
		{&s.s3, netip.AddrPortFrom(probeIP1, 3480)}, {&s.other, netip.AddrPortFrom(probeOther, 5000)},
		{&s.port2, netip.AddrPortFrom(probeIP1, 3481)},
	} {
		c, err := listenIn(tp.inet, p.ap)
		if err != nil {
			s.close()
			return nil, err
		}
		*p.c = c
	}
	return s, nil
}

func (s *probeServers) close() {
	for _, c := range []*net.UDPConn{s.s1, s.s2, s.s3, s.other, s.port2} {
		if c != nil {
			c.Close()
		}
	}
}

func addrOf(c *net.UDPConn) netip.AddrPort {
	ap := c.LocalAddr().(*net.UDPAddr).AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// recv reads c until a datagram with payload want arrives, and gives up
// after probeWait.
func recv(c *net.UDPConn, want string) (netip.AddrPort, bool) {
	buf := make([]byte, 64)
	c.SetReadDeadline(time.Now().Add(probeWait))
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			return netip.AddrPort{}, false
		}
		if string(buf[:n]) == want {
			return netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), true
		}
	}
}

// measurement is what the probe saw of one host's NAT: the external
// endpoint seen by s1, s2 and s3, and whether a datagram to the one s1 saw
// arrived from the uncontacted address, from s1's address on another
// port and from s1 itself.
type measurement struct {
	local              netip.AddrPort
	obs                [3]netip.AddrPort
	other, port, exact bool
}

func (m measurement) mapping() string {
	switch {
	case m.obs[0] == m.local && m.obs[1] == m.local:
		return "none"
	case m.obs[0] == m.obs[1]:
		return "EIM"
	case m.obs[0] == m.obs[2]:
		return "ADM"
	}
	return "APDM"
}

func (m measurement) filtering() string {
	switch {
	case !m.exact:
		return "closed"
	case m.other && m.port:
		return "EIF"
	case m.port:
		return "ADF"
	case !m.other:
		return "APDF"
	}
	return "inconsistent"
}

// typ is the measured type, named as in §4.1.
func (m measurement) typ() string {
	if mp, f := m.mapping(), m.filtering(); mp != "none" || f != "EIF" {
		return mp + "-" + f
	}
	return "none"
}

func (m measurement) String() string {
	return fmt.Sprintf("%v is seen as %v by %v, %v by %v and %v by %v; to %v arrives from an uncontacted address %v, from the same address on another port %v, from the exact address %v",
		m.local, m.obs[0], netip.AddrPortFrom(probeIP1, 3478), m.obs[1], netip.AddrPortFrom(probeIP2, 3479),
		m.obs[2], netip.AddrPortFrom(probeIP1, 3480), m.obs[0], m.other, m.port, m.exact)
}

// probe measures the mapping and the filtering in front of h from its
// probe port.
func (s *probeServers) probe(h lhost) (measurement, error) {
	m := measurement{local: h.probeLocal()}
	c, err := listenIn(h.ns, m.local)
	if err != nil {
		return m, err
	}
	defer c.Close()
	for i, srv := range []*net.UDPConn{s.s1, s.s2, s.s3} {
		msg := fmt.Sprintf("map%d", i)
		if _, err := c.WriteToUDPAddrPort([]byte(msg), addrOf(srv)); err != nil {
			return m, err
		}
		from, ok := recv(srv, msg)
		if !ok {
			return m, fmt.Errorf("probe server %v received nothing from %v in %v", addrOf(srv), m.local, probeWait)
		}
		m.obs[i] = from
	}
	for i, p := range []struct {
		srv *net.UDPConn
		got *bool
	}{{s.other, &m.other}, {s.port2, &m.port}, {s.s1, &m.exact}} {
		msg := fmt.Sprintf("filter%d", i)
		if _, err := p.srv.WriteToUDPAddrPort([]byte(msg), m.obs[0]); err != nil {
			return m, err
		}
		from, ok := recv(c, msg)
		if ok && from != addrOf(p.srv) {
			return m, fmt.Errorf("a datagram from %v to %v arrived from %v", addrOf(p.srv), m.obs[0], from)
		}
		*p.got = ok
	}
	return m, nil
}

// hairpinMeasurement is the hairpin probe: b's probe socket sends to the
// external endpoint of a's (first), then a's to b's (second).
type hairpinMeasurement struct {
	obsA, obsB, src1, src2 netip.AddrPort
	got1, got2             bool
}

func (h hairpinMeasurement) String() string {
	return fmt.Sprintf("a is %v and b is %v outside; b to a arrived %v (from %v), a to b arrived %v (from %v)",
		h.obsA, h.obsB, h.got1, h.src1, h.got2, h.src2)
}

func (s *probeServers) hairpin(a, b lhost) (hairpinMeasurement, error) {
	var h hairpinMeasurement
	ca, err := listenIn(a.ns, a.probeLocal())
	if err != nil {
		return h, err
	}
	defer ca.Close()
	cb, err := listenIn(b.ns, b.probeLocal())
	if err != nil {
		return h, err
	}
	defer cb.Close()
	for _, p := range []struct {
		c   *net.UDPConn
		obs *netip.AddrPort
		msg string
	}{{ca, &h.obsA, "hpa"}, {cb, &h.obsB, "hpb"}} {
		if _, err := p.c.WriteToUDPAddrPort([]byte(p.msg), addrOf(s.s1)); err != nil {
			return h, err
		}
		from, ok := recv(s.s1, p.msg)
		if !ok {
			return h, fmt.Errorf("probe server %v received nothing from %v", addrOf(s.s1), addrOf(p.c))
		}
		*p.obs = from
	}
	if _, err := cb.WriteToUDPAddrPort([]byte("hp1"), h.obsA); err != nil {
		return h, err
	}
	h.src1, h.got1 = recv(ca, "hp1")
	if _, err := ca.WriteToUDPAddrPort([]byte("hp2"), h.obsB); err != nil {
		return h, err
	}
	h.src2, h.got2 = recv(cb, "hp2")
	return h, nil
}

// fidelity measures every NAT in front of a and b before they are used,
// and returns what does not behave as declared. Behind a shared NAT the
// hairpin probe must see: b to a only with hairpin and EIF; a to b with
// hairpin and EIF or EIM (b's mapping already sent to a's endpoint, which
// a's EIM mapping keeps); arrivals from the external address (REQ-9a),
// and with EIM from a's own endpoint.
func (tp *topo) fidelity() error {
	srv, err := tp.servers()
	if err != nil {
		return err
	}
	defer srv.close()
	var problems []string
	for _, h := range []lhost{tp.a, tp.b} {
		m, err := srv.probe(h)
		if err != nil {
			return fmt.Errorf("%s: %v", h.ns, err)
		}
		if got := m.typ(); got != h.typ {
			problems = append(problems, fmt.Sprintf("%s declared %s, measured %s: %v", h.ns, h.typ, got, m))
		}
	}
	if tp.shared {
		hm, err := srv.hairpin(tp.a, tp.b)
		if err != nil {
			return fmt.Errorf("hairpin: %v", err)
		}
		mp, f := behaviors(tp.sharedTyp)
		want1 := tp.hairpin && f == "EIF"
		want2 := tp.hairpin && (f == "EIF" || mp == "EIM")
		if hm.got1 != want1 || hm.got2 != want2 ||
			hm.got1 && hm.src1.Addr() != tp.sharedExt || hm.got2 && hm.src2.Addr() != tp.sharedExt ||
			hm.got2 && mp == "EIM" && hm.src2 != hm.obsA {
			problems = append(problems, fmt.Sprintf("%s hairpin=%v at %v: want b to a %v and a to b %v from the external address, measured %v",
				tp.sharedTyp, tp.hairpin, tp.sharedExt, want1, want2, hm))
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// The mesh on a real topology: the coordination, its reflexive service
// and the relay in the internet namespace, malla nodes a and b in their
// hosts.
const (
	linuxAuthKey = "matrix"
	linuxAdmin   = "matrix-admin"
)

type linuxMesh struct {
	malla string
	cfg   map[string]string // node configuration file by namespace
	addr  map[string]string // mesh address by namespace
}

// buildBinaries builds malla, malla-coord and malla-relay once per test.
func buildBinaries(t testing.TB) map[string]string {
	t.Helper()
	for _, tool := range []string{"go", "nft"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required: %v", tool, err)
		}
	}
	dir := t.TempDir()
	bin := map[string]string{}
	for _, name := range []string{"malla", "malla-coord", "malla-relay"} {
		bin[name] = filepath.Join(dir, name)
		if out, err := exec.Command("go", "build", "-o", bin[name], "github.com/CesarManzoCode/malla-wg/cmd/"+name).CombinedOutput(); err != nil {
			t.Fatalf("go build %s: %v\n%s", name, err, out)
		}
	}
	return bin
}

func startMesh(t testing.TB, tp *topo, bin map[string]string) *linuxMesh {
	t.Helper()
	svc := svcAddr.String()
	writeJSON(t, filepath.Join(tp.dir, "relay.json"), map[string]any{
		"listen": svc + ":8443", "state_dir": filepath.Join(tp.dir, "relay"),
	})
	line := startDaemon(t, tp.inet, "malla-relay: listen ", bin["malla-relay"], "-config", filepath.Join(tp.dir, "relay.json"))
	relayFP := lastField(line)
	writeFile(t, filepath.Join(tp.dir, "policy.json"), `{"rules": [{"src": ["a"], "dst": ["b"]}]}`)
	writeJSON(t, filepath.Join(tp.dir, "coord.json"), map[string]any{
		"listen": svc + ":8444", "stun_listen": svc + ":3478",
		"state_dir": filepath.Join(tp.dir, "coord"), "admin_token": linuxAdmin,
		"auth_keys": []string{linuxAuthKey}, "policy_file": "policy.json",
		"relay": "https://" + svc + ":8443",
	})
	line = startDaemon(t, tp.inet, "malla-coord: listen ", bin["malla-coord"], "-config", filepath.Join(tp.dir, "coord.json"))
	coordFP := lastField(line)

	m := &linuxMesh{malla: bin["malla"], cfg: map[string]string{}, addr: map[string]string{}}
	for _, n := range []struct {
		h    lhost
		name string
	}{{tp.a, "a"}, {tp.b, "b"}} {
		var priv [32]byte
		rand.Read(priv[:])
		keyFile := filepath.Join(tp.dir, n.name+".key")
		writeFile(t, keyFile, base64.StdEncoding.EncodeToString(priv[:])+"\n")
		m.cfg[n.h.ns] = filepath.Join(tp.dir, n.name+".json")
		writeJSON(t, m.cfg[n.h.ns], map[string]any{
			"private_key_file": keyFile, "listen_port": n.h.port,
			"coord_url": "https://" + svc + ":8444", "coord_fingerprint": coordFP,
			"auth_key": linuxAuthKey, "relay_fingerprint": relayFP,
			"state_dir": filepath.Join(tp.dir, n.name), "tun_name": "malla0", "name": n.name,
		})
		line := startDaemon(t, n.h.ns, "malla: up ", bin["malla"], "up", "-config", m.cfg[n.h.ns])
		// malla: up <tun> <addr>/<bits> listen <port> key <key>
		f := strings.Fields(line)
		if len(f) < 4 {
			t.Fatalf("unexpected line %q", line)
		}
		m.addr[n.h.ns] = strings.Split(f[3], "/")[0]
	}
	return m
}

// cli runs `malla <args> -config <node.json>` in ns and returns its
// output and exit code.
func (m *linuxMesh) cli(ns string, args ...string) (string, int, error) {
	argv := append(append([]string{"netns", "exec", ns, m.malla}, args...), "-config", m.cfg[ns])
	cmd := exec.Command("ip", argv...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return out.String(), exit.ExitCode(), nil
	}
	return out.String(), 0, err
}

// waitDirect runs `malla wait-direct -timeout 30s` on a for b and on b for
// a at once, and reports whether each exited 0.
func (m *linuxMesh) waitDirect(tp *topo) ([2]bool, error) {
	var ok [2]bool
	var errs [2]error
	var wg sync.WaitGroup
	for i, s := range []struct{ ns, peer string }{{tp.a.ns, "b"}, {tp.b.ns, "a"}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, code, err := m.cli(s.ns, "wait-direct", "-peer", s.peer, "-timeout", "30s")
			switch {
			case err != nil:
				errs[i] = err
			case code != 0 && code != 1:
				errs[i] = fmt.Errorf("wait-direct in %s exited %d: %s", s.ns, code, out)
			}
			ok[i] = err == nil && code == 0
		}()
	}
	wg.Wait()
	return ok, errors.Join(errs[0], errs[1])
}

// path returns the path `malla status` in ns reports for peer, or "".
func (m *linuxMesh) path(ns, peer string) (string, string) {
	out, _, _ := m.cli(ns, "status")
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) == 4 && f[0] == peer {
			return f[2], out
		}
	}
	return "", out
}

// startDaemon runs args inside ns until t ends and returns the first line
// of its standard output that starts with ready.
func startDaemon(t testing.TB, ns, ready string, args ...string) string {
	t.Helper()
	log := &syncBuffer{}
	cmd := exec.Command("ip", append([]string{"netns", "exec", ns}, args...)...)
	cmd.Stderr = log
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(args[0])
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
		t.Logf("%s in %s log:\n%s", name, ns, log.String())
	})
	lines := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), ready) {
				select {
				case lines <- sc.Text():
				default:
				}
			}
		}
		close(lines)
	}()
	select {
	case line, ok := <-lines:
		if !ok {
			t.Fatalf("%s in %s exited before it was ready; log:\n%s", name, ns, log.String())
		}
		return line
	case <-time.After(15 * time.Second):
		t.Fatalf("%s in %s was not ready within 15 s; log:\n%s", name, ns, log.String())
	}
	return ""
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func lastField(line string) string {
	f := strings.Fields(line)
	return f[len(f)-1]
}

func writeFile(t testing.TB, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeJSON(t testing.TB, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(b))
}

// eachCell runs fn for every cell in its own parallel subtest, at most
// linuxParallel at once, each on a free slot of namespace names. The slot
// returns to the pool only after the subtest's cleanups removed its
// namespaces and stopped its daemons.
func eachCell(t *testing.T, cells [][2]string, fn func(t *testing.T, slot int, group, cell string)) {
	slots := make(chan int, linuxParallel)
	for i := range linuxParallel {
		slots <- i
	}
	t.Run("cells", func(t *testing.T) {
		for _, c := range cells {
			t.Run(c[0]+":"+c[1], func(t *testing.T) {
				t.Parallel()
				slot := <-slots
				t.Cleanup(func() { slots <- slot })
				fn(t, slot, c[0], c[1])
			})
		}
	})
}

// realCells returns the cells of group that have a real oracle (no ADM-*
// type, §4.4) and those that do not.
func realCells(theory map[string]map[string]string, group string) (withOracle [][2]string, simOnly []string) {
	for _, cell := range sortedCells(theory[group]) {
		if strings.Contains(cell, "ADM-") {
			simOnly = append(simOnly, group+" "+cell)
			continue
		}
		withOracle = append(withOracle, [2]string{group, cell})
	}
	return withOracle, simOnly
}

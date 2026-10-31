//go:build linux

package e2e

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/CesarManzoCode/malla-wg/internal/x25519"
	"github.com/CesarManzoCode/malla-wg/verify/netns"
)

// TestCritDataplaneAllowedIPs is criterion 13: three namespaces A, B and C
// run real malla nodes on Linux TUNs; A routes 10.200.0.2/32 to B and
// 10.200.0.3/32 to C. Pings from A get answers and each leaves only toward
// its own peer; a datagram that B tunnels with a forged inner source is
// dropped by A, while the same datagram with B's own source arrives.
func TestCritDataplaneAllowedIPs(t *testing.T) {
	netns.Require(t)
	netns.Run(t, dataplane)
}

type node struct {
	ns, addr string
	priv     [32]byte
	pub      string
	log      *syncBuffer
}

func dataplane(t *testing.T) {
	for _, tool := range []string{"ping", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required: %v", tool, err)
		}
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "malla")
	if out, err := exec.Command("go", "build", "-o", bin, "github.com/CesarManzoCode/malla-wg/cmd/malla").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	netns.Add(t, "A", "B", "C")
	netns.Veth(t, "A", "ab", "192.168.12.1/24", "B", "ba", "192.168.12.2/24")
	netns.Veth(t, "A", "ac", "192.168.13.1/24", "C", "ca", "192.168.13.3/24")

	nodes := map[string]*node{}
	for _, n := range []*node{{ns: "A", addr: "10.200.0.1"}, {ns: "B", addr: "10.200.0.2"}, {ns: "C", addr: "10.200.0.3"}} {
		if _, err := rand.Read(n.priv[:]); err != nil {
			t.Fatal(err)
		}
		pub := x25519.PublicKey(n.priv)
		n.pub = base64.StdEncoding.EncodeToString(pub[:])
		nodes[n.ns] = n
	}
	peer := func(ns, endpoint string, allowed string) map[string]any {
		return map[string]any{"public_key": nodes[ns].pub, "endpoint": endpoint, "allowed_ips": []string{allowed}}
	}
	peers := map[string][]map[string]any{
		"A": {peer("B", "192.168.12.2:51820", "10.200.0.2/32"), peer("C", "192.168.13.3:51820", "10.200.0.3/32")},
		"B": {peer("A", "192.168.12.1:51820", "10.200.0.1/32")},
		"C": {peer("A", "192.168.13.1:51820", "10.200.0.1/32")},
	}
	for _, ns := range []string{"A", "B", "C"} {
		startNode(t, bin, dir, nodes[ns], peers[ns])
	}

	// (1) Each ping is answered, and its datagrams reach only its peer's
	// socket. The node is the only UDP user of B and C, so the kernel's
	// per-namespace UDP counters are the counters of its socket.
	for _, c := range []struct{ dst, via, other string }{
		{"10.200.0.2", "B", "C"},
		{"10.200.0.3", "C", "B"},
	} {
		viaBefore, otherBefore := udpInDatagrams(t, c.via), udpInDatagrams(t, c.other)
		if out, err := netns.Exec("A", "ping", "-c", "1", "-W", "5", c.dst); err != nil {
			t.Fatalf("ping %s from A: %v\n%s", c.dst, err, out)
		}
		viaAfter, otherAfter := udpInDatagrams(t, c.via), udpInDatagrams(t, c.other)
		if viaAfter == viaBefore {
			t.Errorf("ping %s: no datagram reached %s's socket", c.dst, c.via)
		}
		if otherAfter != otherBefore {
			t.Errorf("ping %s: %d datagrams reached %s's socket, want 0", c.dst, otherAfter-otherBefore, c.other)
		}
	}

	// (2) A test socket listens on A's tunnel address; B injects into its
	// TUN, through a raw socket, a UDP datagram with the forged source
	// 10.200.0.99 and then a control datagram with its own source.
	var listener *net.UDPConn
	if err := netns.Do("A", func() (err error) {
		listener, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(10, 200, 0, 1), Port: 7777})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var raw int
	if err := netns.Do("B", func() (err error) {
		raw, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
		return err
	}); err != nil {
		t.Fatalf("raw socket in B: %v", err)
	}
	defer unix.Close(raw)
	dst := &unix.SockaddrInet4{Addr: [4]byte{10, 200, 0, 1}}
	for _, d := range []struct{ src, payload string }{{"10.200.0.99", "spoofed"}, {"10.200.0.2", "control"}} {
		if err := unix.Sendto(raw, udpPacket(d.src, "10.200.0.1", 5555, 7777, []byte(d.payload)), 0, dst); err != nil {
			t.Fatalf("send %s datagram: %v", d.payload, err)
		}
	}

	got := map[string]string{}
	listener.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 1500)
	for {
		n, from, err := listener.ReadFromUDPAddrPort(buf)
		if err != nil {
			break // deadline
		}
		got[string(buf[:n])] = from.String()
		if string(buf[:n]) == "control" {
			// The spoofed datagram went first; give it a moment more.
			listener.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		}
	}
	if from, ok := got["control"]; !ok || from != "10.200.0.2:5555" {
		t.Errorf("control datagram: received %v from %q, want from 10.200.0.2:5555", ok, from)
	}
	if from, ok := got["spoofed"]; ok {
		t.Errorf("A delivered the spoofed datagram from %s", from)
	}
	if !waitFor(5*time.Second, func() bool { return strings.Contains(nodes["A"].log.String(), "reason=allowedips") }) {
		t.Errorf("A logged no allowedips drop; log:\n%s", nodes["A"].log.String())
	}
}

// startNode writes ns's key and configuration and runs `malla up` inside
// ns until the test ends.
func startNode(t *testing.T, bin, dir string, n *node, peers []map[string]any) {
	t.Helper()
	keyFile := filepath.Join(dir, n.ns+".key")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(n.priv[:])+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := json.Marshal(map[string]any{
		"private_key_file": keyFile,
		"listen_port":      51820,
		"state_dir":        filepath.Join(dir, n.ns),
		"tun_name":         "malla0",
		"address":          n.addr + "/24",
		"peers":            peers,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfgFile := filepath.Join(dir, n.ns+".json")
	if err := os.WriteFile(cfgFile, cfg, 0o600); err != nil {
		t.Fatal(err)
	}

	n.log = &syncBuffer{}
	cmd := exec.Command("ip", "netns", "exec", n.ns, bin, "up", "-config", cfgFile)
	cmd.Stderr = n.log
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
		t.Logf("malla %s log:\n%s", n.ns, n.log.String())
	})
	ready := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "malla: up ") {
				ready <- sc.Text()
			}
		}
		close(ready)
	}()
	select {
	case line, ok := <-ready:
		if !ok {
			t.Fatalf("malla in %s exited before coming up; log:\n%s", n.ns, n.log.String())
		}
		t.Logf("%s: %s", n.ns, line)
	case <-time.After(15 * time.Second):
		t.Fatalf("malla in %s did not come up within 15 s; log:\n%s", n.ns, n.log.String())
	}
}

// udpInDatagrams reads Udp InDatagrams from /proc/net/snmp inside ns.
func udpInDatagrams(t *testing.T, ns string) uint64 {
	t.Helper()
	var header []string
	for _, line := range strings.Split(string(netns.MustExec(t, ns, "cat", "/proc/net/snmp")), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "Udp:" {
			continue
		}
		if header == nil {
			header = fields
			continue
		}
		for i, name := range header {
			if name == "InDatagrams" && i < len(fields) {
				v, err := strconv.ParseUint(fields[i], 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				return v
			}
		}
	}
	t.Fatalf("no Udp InDatagrams in /proc/net/snmp of %s", ns)
	return 0
}

// udpPacket builds an IPv4/UDP packet for a raw IPPROTO_RAW socket. The
// kernel fills in the IP checksum; a zero UDP checksum means none (IPv4).
func udpPacket(src, dst string, sport, dport uint16, payload []byte) []byte {
	b := make([]byte, 28+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8], b[9] = 64, unix.IPPROTO_UDP
	copy(b[12:16], net.ParseIP(src).To4())
	copy(b[16:20], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(b[20:22], sport)
	binary.BigEndian.PutUint16(b[22:24], dport)
	binary.BigEndian.PutUint16(b[24:26], uint16(8+len(payload)))
	copy(b[28:], payload)
	return b
}

func waitFor(d time.Duration, cond func() bool) bool {
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return cond()
}

// syncBuffer is a bytes.Buffer safe for a process writing while the test
// reads.
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

//go:build linux

package e2e

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CesarManzoCode/malla-wg/verify/netns"
)

// Migration transfer (contract §6): 16 MiB at a paced rate, so that it
// lasts longer than the path change that starts 2 s in.
const (
	migrationTransfer = 16 << 20
	migrationRate     = 1 << 20 // bytes per second: about 16 s
	migrationChunk    = 64 << 10
	migrationUnblock  = 2 * time.Second
)

// TestCritPathCLI is criterion 19: with the router dropping UDP between A
// and B, `malla status` on A reports relay for b and `malla wait-direct
// -peer b -timeout 5s` exits non-zero. Once the rule is gone,
// `wait-direct -timeout 30s` exits 0 and status reports direct. The test
// reads the raw output of the CLI.
func TestCritPathCLI(t *testing.T) {
	netns.Require(t)
	netns.Run(t, pathCLI)
}

func pathCLI(t *testing.T) {
	m := startPathMesh(t)
	m.waitPath(t, "A", "b", "relay", 30*time.Second)

	out, errOut, code := m.cli(t, "A", "wait-direct", "-peer", "b", "-timeout", "5s")
	t.Logf("wait-direct -timeout 5s with UDP blocked: exit %d, stdout %q, stderr %q", code, out, errOut)
	if code == 0 {
		t.Fatal("wait-direct exited 0 while UDP between A and B is dropped")
	}
	out, _, _ = m.cli(t, "A", "status")
	if path, _ := statusOf(t, out, "b", m.addr["B"]); path != "relay" {
		t.Fatalf("status after wait-direct with UDP blocked: %q, want relay for b", out)
	}

	m.unblock(t)
	start := time.Now()
	out, errOut, code = m.cli(t, "A", "wait-direct", "-peer", "b", "-timeout", "30s")
	t.Logf("wait-direct -timeout 30s after unblocking: exit %d in %v, stdout %q, stderr %q",
		code, time.Since(start).Round(time.Millisecond), out, errOut)
	if code != 0 {
		t.Fatalf("wait-direct exited %d after the UDP rule was removed", code)
	}
	out, _, code = m.cli(t, "A", "status")
	t.Logf("status after wait-direct: exit %d, %q", code, out)
	if path, ep := statusOf(t, out, "b", m.addr["B"]); code != 0 || path != "direct" || ep == "-" {
		t.Fatalf("status = %q (exit %d), want direct with an endpoint for b", out, code)
	}
}

// TestCritMigrationNoCut is criterion 20: with UDP blocked the path
// starts on the relay, and a paced 16 MiB TCP transfer through the tunnel
// starts there. 2 s in the block is removed and the path turns direct
// during the transfer. The receiver gets exactly 16 MiB with the same
// SHA-256, status reports direct, and neither node sent an initiation or
// derived a session after the block was removed.
func TestCritMigrationNoCut(t *testing.T) {
	netns.Require(t)
	netns.Run(t, migrationNoCut)
}

func migrationNoCut(t *testing.T) {
	m := startPathMesh(t)
	m.waitPath(t, "A", "b", "relay", 30*time.Second)

	data := make([]byte, migrationTransfer)
	rand.Read(data)
	want := sha256.Sum256(data)
	var ln net.Listener
	if err := netns.Do("B", func() (err error) {
		ln, err = net.Listen("tcp4", net.JoinHostPort(m.addr["B"], "9001"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type result struct {
		sum [32]byte
		n   int64
		err error
	}
	got := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- result{err: err}
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(2 * time.Minute))
		h := sha256.New()
		n, err := io.Copy(h, c)
		var r result
		copy(r.sum[:], h.Sum(nil))
		r.n, r.err = n, err
		got <- r
	}()
	var conn net.Conn
	for dial := time.Now(); conn == nil; {
		if time.Since(dial) > time.Minute {
			t.Fatalf("no TCP connection from A to %s:9001 through the tunnel in 60 s", m.addr["B"])
		}
		if err := netns.Do("A", func() (err error) {
			conn, err = net.DialTimeout("tcp4", net.JoinHostPort(m.addr["B"], "9001"), 3*time.Second)
			return err
		}); err != nil {
			time.Sleep(200 * time.Millisecond)
		}
	}
	defer conn.Close()

	// The paced writer: chunk k leaves no earlier than its share of the
	// rate allows.
	var written atomic.Int64
	writeDone := make(chan error, 1)
	start := time.Now()
	go func() {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Minute))
		for off := 0; off < len(data); off += migrationChunk {
			end := min(off+migrationChunk, len(data))
			if _, err := conn.Write(data[off:end]); err != nil {
				writeDone <- err
				return
			}
			written.Store(int64(end))
			time.Sleep(time.Until(start.Add(time.Duration(end) * time.Second / migrationRate)))
		}
		writeDone <- conn.(*net.TCPConn).CloseWrite()
	}()

	time.Sleep(time.Until(start.Add(migrationUnblock)))
	out, _, _ := m.cli(t, "A", "status")
	if path, _ := statusOf(t, out, "b", m.addr["B"]); path != "relay" {
		t.Fatalf("status %v into the transfer, before unblocking: %q, want relay for b", time.Since(start).Round(time.Millisecond), out)
	}
	before := written.Load()
	if before == 0 {
		t.Fatal("nothing written in the first 2 s: the transfer did not start on the relay")
	}
	sessions := m.sessionEvents()
	m.unblock(t)
	unblocked := time.Since(start)
	t.Logf("UDP unblocked %v into the transfer, %d bytes written on the relay", unblocked.Round(time.Millisecond), before)

	switchAt := time.Duration(-1)
	var atSwitch int64
	var werr error
	writing := true
	for writing && switchAt < 0 {
		out, _, _ := m.cli(t, "A", "status")
		if path, ep := statusOf(t, out, "b", m.addr["B"]); path == "direct" {
			switchAt, atSwitch = time.Since(start), written.Load()
			t.Logf("path change: relay -> direct %s at %v into the transfer (%v after unblocking), %d of %d bytes written",
				ep, switchAt.Round(time.Millisecond), (switchAt - unblocked).Round(time.Millisecond), atSwitch, len(data))
			break
		}
		select {
		case werr = <-writeDone:
			writing = false
		case <-time.After(100 * time.Millisecond):
		}
	}
	if switchAt < 0 || atSwitch >= int64(len(data)) {
		t.Fatalf("the path did not turn direct during the transfer (seen at %v, %d of %d bytes written)", switchAt, atSwitch, len(data))
	}
	if writing {
		werr = <-writeDone
	}
	if werr != nil {
		t.Fatalf("write: %v", werr)
	}
	t.Logf("sender done %v after the start", time.Since(start).Round(time.Millisecond))
	r := <-got
	if r.err != nil || r.n != migrationTransfer || r.sum != want {
		t.Fatalf("B received %d bytes (err %v) with SHA-256 %x, want %d bytes with %x", r.n, r.err, r.sum, migrationTransfer, want)
	}
	t.Logf("B received %d bytes with SHA-256 %x in %v", r.n, r.sum, time.Since(start).Round(time.Millisecond))

	out, _, code := m.cli(t, "A", "status")
	t.Logf("status at the end: exit %d, %q", code, out)
	if path, _ := statusOf(t, out, "b", m.addr["B"]); code != 0 || path != "direct" {
		t.Fatalf("status at the end = %q (exit %d), want direct for b", out, code)
	}
	if after := m.sessionEvents(); after != sessions {
		t.Fatalf("handshake and rekey events went from %d to %d across the migration: it restarted the handshake", sessions, after)
	}
}

// pathMesh is the topology of the relay test: A, B and S on their own
// segments of the router R, which drops UDP between A and B until
// unblock. S runs the coordination and the relay, A and B mesh nodes
// named a and b.
type pathMesh struct {
	malla string
	cfg   map[string]string  // node configuration file by namespace
	addr  map[string]string  // mesh address by namespace
	node  map[string]*daemon // malla up by namespace
}

func startPathMesh(t *testing.T) *pathMesh {
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
	netns.Add(t, "A", "B", "S", "R")
	netns.Veth(t, "A", "ar", "192.168.1.2/24", "R", "ra", "192.168.1.1/24")
	netns.Veth(t, "B", "br", "192.168.2.2/24", "R", "rb", "192.168.2.1/24")
	netns.Veth(t, "S", "sr", "192.168.3.2/24", "R", "rs", "192.168.3.1/24")
	for ns, gw := range map[string]string{"A": "192.168.1.1", "B": "192.168.2.1", "S": "192.168.3.1"} {
		netns.MustExec(t, ns, "ip", "route", "add", "default", "via", gw)
	}
	netns.MustExec(t, "R", "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward")
	rules := filepath.Join(dir, "r.nft")
	writeFile(t, rules, `table inet mallapath {
	chain forward {
		type filter hook forward priority filter; policy accept;
		ip saddr 192.168.1.0/24 ip daddr 192.168.2.0/24 meta l4proto udp counter drop
		ip saddr 192.168.2.0/24 ip daddr 192.168.1.0/24 meta l4proto udp counter drop
	}
}
`)
	netns.MustExec(t, "R", "nft", "-f", rules)

	writeJSON(t, filepath.Join(dir, "relay.json"), map[string]any{
		"listen": "192.168.3.2:8443", "state_dir": filepath.Join(dir, "relay"),
	})
	line, _ := startDaemon(t, "S", "malla-relay: listen ", bin["malla-relay"], "-config", filepath.Join(dir, "relay.json"))
	relayFP := lastField(line)
	writeFile(t, filepath.Join(dir, "policy.json"), `{"rules": [{"src": ["a"], "dst": ["b"]}]}`)
	writeJSON(t, filepath.Join(dir, "coord.json"), map[string]any{
		"listen": "192.168.3.2:8444", "stun_listen": "192.168.3.2:3478",
		"state_dir": filepath.Join(dir, "coord"), "admin_token": testAdmin,
		"auth_keys": []string{testAuthKey}, "policy_file": "policy.json",
		"relay": "https://192.168.3.2:8443",
	})
	line, _ = startDaemon(t, "S", "malla-coord: listen ", bin["malla-coord"], "-config", filepath.Join(dir, "coord.json"))
	coordFP := lastField(line)

	m := &pathMesh{malla: bin["malla"], cfg: map[string]string{}, addr: map[string]string{}, node: map[string]*daemon{}}
	for _, n := range []struct{ ns, name string }{{"A", "a"}, {"B", "b"}} {
		var priv [32]byte
		rand.Read(priv[:])
		keyFile := filepath.Join(dir, n.ns+".key")
		writeFile(t, keyFile, base64.StdEncoding.EncodeToString(priv[:])+"\n")
		m.cfg[n.ns] = filepath.Join(dir, n.ns+".json")
		writeJSON(t, m.cfg[n.ns], map[string]any{
			"private_key_file": keyFile, "listen_port": 51820,
			"coord_url": "https://192.168.3.2:8444", "coord_fingerprint": coordFP,
			"auth_key": testAuthKey, "relay_fingerprint": relayFP,
			"state_dir": filepath.Join(dir, n.ns), "tun_name": "malla0", "name": n.name,
		})
		line, d := startDaemon(t, n.ns, "malla: up ", bin["malla"], "up", "-config", m.cfg[n.ns])
		// malla: up <tun> <addr>/<bits> listen <port> key <key>
		f := strings.Fields(line)
		if len(f) < 4 {
			t.Fatalf("unexpected line %q", line)
		}
		m.addr[n.ns], m.node[n.ns] = strings.Split(f[3], "/")[0], d
	}
	return m
}

// unblock removes the router's UDP rule.
func (m *pathMesh) unblock(t *testing.T) {
	t.Helper()
	netns.MustExec(t, "R", "nft", "delete", "table", "inet", "mallapath")
}

// cli runs `malla <args> -config <node.json>` in ns and returns its raw
// standard output and error and its exit code.
func (m *pathMesh) cli(t *testing.T, ns string, args ...string) (string, string, int) {
	t.Helper()
	argv := append([]string{"netns", "exec", ns, m.malla}, args...)
	cmd := exec.Command("ip", append(argv, "-config", m.cfg[ns])...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return stdout.String(), stderr.String(), 0
	case errors.As(err, &exit):
		return stdout.String(), stderr.String(), exit.ExitCode()
	}
	t.Fatalf("malla %s in %s: %v", strings.Join(args, " "), ns, err)
	return "", "", 0
}

// waitPath polls `malla status` in ns until peer shows path, and fails
// after d.
func (m *pathMesh) waitPath(t *testing.T, ns, peer, path string, d time.Duration) {
	t.Helper()
	var out, errOut string
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		out, errOut, _ = m.cli(t, ns, "status")
		if p, _ := statusOf(t, out, peer, ""); p == path {
			t.Logf("status in %s: %q", ns, out)
			return
		}
	}
	t.Fatalf("status in %s never showed %s for %s within %v; last stdout %q, stderr %q", ns, path, peer, d, out, errOut)
}

// sessionEvents counts the handshake and rekey events A and B logged.
func (m *pathMesh) sessionEvents() int {
	c := 0
	for _, d := range m.node {
		log := d.log.String()
		c += strings.Count(log, "malla: handshake ") + strings.Count(log, "malla: rekey ")
	}
	return c
}

// statusOf finds the line `<name> <addr> <path> <endpoint>` of peer in
// the raw output of `malla status` and returns its path and endpoint, or
// "" if there is none. A line for peer with another address than addr
// (if addr is set) fails the test.
func statusOf(t *testing.T, out, peer, addr string) (string, string) {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 4 || f[0] != peer {
			continue
		}
		if addr != "" && f[1] != addr {
			t.Fatalf("status line %q: address %s, want %s", line, f[1], addr)
		}
		return f[2], f[3]
	}
	return "", ""
}

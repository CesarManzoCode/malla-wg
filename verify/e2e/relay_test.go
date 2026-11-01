//go:build linux

package e2e

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/chachapoly"
	"github.com/CesarManzoCode/malla-wg/internal/noise"
	"github.com/CesarManzoCode/malla-wg/internal/relay"
	"github.com/CesarManzoCode/malla-wg/internal/x25519"
	"github.com/CesarManzoCode/malla-wg/verify/netns"
)

// relayTransfer is the size of the TCP transfer through the tunnel.
const relayTransfer = 4 << 20

// TestCritRelayHTTPSUDPBlocked is criterion 21: namespaces A and B run
// mesh nodes, S runs the coordination and the relay, and a router R joins
// them and drops every UDP datagram between A and B while TCP to S passes.
// A 4 MiB TCP transfer from A to B through the tunnel arrives with the
// same SHA-256. Then the relay's capture_file is examined: every payload
// is a WireGuard or disco message, the transfer's plaintext marker
// appears in no captured byte, and no captured transport message opens
// with any key the relay holds (none of them is a session key).
func TestCritRelayHTTPSUDPBlocked(t *testing.T) {
	netns.Require(t)
	netns.Run(t, relayBlocked)
}

func relayBlocked(t *testing.T) {
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

	// A, B and S hang off the router R, each on its own segment.
	netns.Add(t, "A", "B", "S", "R")
	netns.Veth(t, "A", "ar", "192.168.1.2/24", "R", "ra", "192.168.1.1/24")
	netns.Veth(t, "B", "br", "192.168.2.2/24", "R", "rb", "192.168.2.1/24")
	netns.Veth(t, "S", "sr", "192.168.3.2/24", "R", "rs", "192.168.3.1/24")
	for ns, gw := range map[string]string{"A": "192.168.1.1", "B": "192.168.2.1", "S": "192.168.3.1"} {
		netns.MustExec(t, ns, "ip", "route", "add", "default", "via", gw)
	}
	netns.MustExec(t, "R", "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward")
	rules := filepath.Join(dir, "r.nft")
	writeFile(t, rules, `table inet mallae2e {
	chain forward {
		type filter hook forward priority filter; policy accept;
		ip saddr 192.168.1.0/24 ip daddr 192.168.2.0/24 meta l4proto udp counter drop
		ip saddr 192.168.2.0/24 ip daddr 192.168.1.0/24 meta l4proto udp counter drop
	}
}
`)
	netns.MustExec(t, "R", "nft", "-f", rules)
	defer func() {
		out, _ := netns.Exec("R", "nft", "list", "table", "inet", "mallae2e")
		t.Logf("router rules after the test (UDP between A and B dropped):\n%s", out)
	}()

	// The relay first, for its fingerprint; then the coordination, which
	// announces the relay in the map.
	relayDir := filepath.Join(dir, "relay")
	capture := filepath.Join(dir, "capture.bin")
	writeJSON(t, filepath.Join(dir, "relay.json"), map[string]any{
		"listen": "192.168.3.2:8443", "state_dir": relayDir, "capture_file": capture,
	})
	line, relayProc := startDaemon(t, "S", "malla-relay: listen ", bin["malla-relay"], "-config", filepath.Join(dir, "relay.json"))
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

	addr := map[string]string{}
	for _, n := range []struct{ ns, name string }{{"A", "a"}, {"B", "b"}} {
		var priv [32]byte
		rand.Read(priv[:])
		keyFile := filepath.Join(dir, n.ns+".key")
		writeFile(t, keyFile, base64.StdEncoding.EncodeToString(priv[:])+"\n")
		cfg := filepath.Join(dir, n.ns+".json")
		writeJSON(t, cfg, map[string]any{
			"private_key_file": keyFile, "listen_port": 51820,
			"coord_url": "https://192.168.3.2:8444", "coord_fingerprint": coordFP,
			"auth_key": testAuthKey, "relay_fingerprint": relayFP,
			"state_dir": filepath.Join(dir, n.ns), "tun_name": "malla0", "name": n.name,
		})
		line, _ := startDaemon(t, n.ns, "malla: up ", bin["malla"], "up", "-config", cfg)
		// malla: up <tun> <addr>/<bits> listen <port> key <key>
		f := strings.Fields(line)
		if len(f) < 4 {
			t.Fatalf("unexpected line %q", line)
		}
		addr[n.ns] = strings.Split(f[3], "/")[0]
		pub := x25519.PublicKey(priv)
		t.Logf("%s: %s key %s", n.ns, addr[n.ns], base64.StdEncoding.EncodeToString(pub[:]))
	}

	// The data: blocks of 1 KiB that each start with the marker.
	var mark [8]byte
	rand.Read(mark[:])
	marker := []byte("malla-plaintext-marker-" + hex.EncodeToString(mark[:]))
	data := make([]byte, relayTransfer)
	rand.Read(data)
	for off := 0; off < len(data); off += 1024 {
		copy(data[off:], marker)
	}
	want := sha256.Sum256(data)

	var ln net.Listener
	if err := netns.Do("B", func() (err error) {
		ln, err = net.Listen("tcp4", net.JoinHostPort(addr["B"], "9000"))
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

	// Dial until the tunnel carries the SYN: the map, the handshake and
	// the relay connection settle in the first seconds.
	var conn net.Conn
	start := time.Now()
	for conn == nil {
		if time.Since(start) > time.Minute {
			t.Fatalf("no TCP connection from A to %s:9000 through the tunnel in 60 s", addr["B"])
		}
		if err := netns.Do("A", func() (err error) {
			conn, err = net.DialTimeout("tcp4", net.JoinHostPort(addr["B"], "9000"), 3*time.Second)
			return err
		}); err != nil {
			time.Sleep(200 * time.Millisecond)
		}
	}
	t.Logf("TCP connection through the tunnel after %v", time.Since(start).Round(time.Millisecond))
	conn.SetWriteDeadline(time.Now().Add(2 * time.Minute))
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.(*net.TCPConn).CloseWrite()
	r := <-got
	conn.Close()
	if r.err != nil || r.n != relayTransfer || r.sum != want {
		t.Fatalf("B received %d bytes (err %v) with SHA-256 %x, want %d bytes with %x", r.n, r.err, r.sum, relayTransfer, want)
	}
	t.Logf("%d bytes from A to B with SHA-256 %x in %v", r.n, r.sum, time.Since(start).Round(time.Millisecond))

	// Stop the relay so the capture is complete, then examine it.
	relayProc.stop()
	raw, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, marker) {
		t.Fatal("the plaintext marker appears in the capture file")
	}
	recs := captureRecords(t, raw)
	byType := map[string]int{}
	var transportBytes int
	for i, rec := range recs {
		if bytes.Contains(rec, marker) {
			t.Fatalf("captured payload %d holds the plaintext marker", i)
		}
		switch {
		case bytes.HasPrefix(rec, []byte("mallaDSC")):
			byType["disco"]++
		case noise.MessageType(rec) != 0:
			byType[fmt.Sprintf("wireguard-%d", rec[0])]++
			if rec[0] == noise.TypeTransport {
				transportBytes += len(rec)
			}
		default:
			t.Fatalf("captured payload %d (%d bytes, % x…) is neither WireGuard nor disco", i, len(rec), rec[:min(16, len(rec))])
		}
	}
	t.Logf("capture: %d payloads %v, %d bytes of transport messages", len(recs), byType, transportBytes)
	if transportBytes < relayTransfer {
		t.Fatalf("the relay forwarded %d bytes of transport messages, fewer than the %d of the transfer: it did not go through the relay", transportBytes, relayTransfer)
	}

	// Every key the relay holds: its TLS private key and certificate.
	keys := relayKeys(t, relayDir)
	tried := 0
	for i, rec := range recs {
		if rec[0] != noise.TypeTransport || noise.MessageType(rec) == 0 {
			continue
		}
		var nonce [12]byte
		copy(nonce[4:], rec[8:16])
		for name, k := range keys {
			tried++
			if _, err := chachapoly.Open(nil, k, nonce[:], rec[16:], nil); err == nil {
				t.Fatalf("captured transport message %d opened with the relay's %s", i, name)
			}
		}
	}
	if tried == 0 {
		t.Fatal("no transport message to try the relay's keys on")
	}
	t.Logf("%d attempts to open captured transport messages with the relay's %d keys: all failed", tried, len(keys))
}

// captureRecords splits a capture file into its payloads (u32 big-endian
// length + bytes, contract §3.2).
func captureRecords(t *testing.T, raw []byte) [][]byte {
	t.Helper()
	var recs [][]byte
	for len(raw) > 0 {
		if len(raw) < 4 {
			t.Fatalf("capture ends with %d stray bytes", len(raw))
		}
		n := binary.BigEndian.Uint32(raw)
		if n == 0 || uint32(len(raw)-4) < n {
			t.Fatalf("capture record of %d bytes with %d left", n, len(raw)-4)
		}
		recs = append(recs, raw[4:4+n])
		raw = raw[4+n:]
	}
	if len(recs) == 0 {
		t.Fatal("the capture file is empty")
	}
	return recs
}

// relayKeys returns, as 32-byte AEAD keys, everything secret or keyed the
// relay keeps: the scalar of its ECDSA key, the digests of that key and of
// its certificate, and the all-zero key.
func relayKeys(t *testing.T, stateDir string) map[string][]byte {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(filepath.Join(stateDir, relay.CertFile), filepath.Join(stateDir, relay.KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("relay key is %T, want ECDSA", cert.PrivateKey)
	}
	scalar, err := priv.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	pemKey, err := os.ReadFile(filepath.Join(stateDir, relay.KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemKey)
	if block == nil {
		t.Fatal("relay key file is not PEM")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Fatal(err)
	}
	pkcs8 := sha256.Sum256(block.Bytes)
	fp := sha256.Sum256(cert.Certificate[0])
	return map[string][]byte{
		"ECDSA scalar":       scalar,
		"SHA-256 of its key": pkcs8[:],
		"certificate digest": fp[:],
		"all-zero key":       make([]byte, 32),
	}
}

// daemon is a process started by startDaemon.
type daemon struct {
	log  *syncBuffer
	once sync.Once
	cmd  *exec.Cmd
}

func (d *daemon) stop() {
	d.once.Do(func() {
		d.cmd.Process.Signal(syscall.SIGTERM)
		d.cmd.Wait()
	})
}

// startDaemon runs args inside ns until the test ends and returns the
// first line of its standard output that starts with ready.
func startDaemon(t *testing.T, ns, ready string, args ...string) (string, *daemon) {
	t.Helper()
	d := &daemon{log: &syncBuffer{}}
	d.cmd = exec.Command("ip", append([]string{"netns", "exec", ns}, args...)...)
	d.cmd.Stderr = d.log
	stdout, err := d.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(args[0])
	t.Cleanup(func() {
		d.stop()
		t.Logf("%s in %s log:\n%s", name, ns, d.log.String())
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
			t.Fatalf("%s in %s exited before it was ready; log:\n%s", name, ns, d.log.String())
		}
		t.Logf("%s: %s", ns, line)
		return line, d
	case <-time.After(15 * time.Second):
		t.Fatalf("%s in %s was not ready within 15 s; log:\n%s", name, ns, d.log.String())
	}
	return "", nil
}

func lastField(line string) string {
	f := strings.Fields(line)
	return f[len(f)-1]
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(b))
}

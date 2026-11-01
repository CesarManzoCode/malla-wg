//go:build linux

package matrix

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CesarManzoCode/malla-wg/verify/netns"
)

// TestCritNATFidelity is criterion 17: before the matrix trusts a real
// NAT, the probe measures it. Every hairpin cell with a real oracle (the
// 6 expressible types, hairpin on and off) and every cgnat_same cell (the
// CGNAT layers, measured composed as rule 3 of §4.2 says) must show the
// declared mapping and filtering from both hosts, and the declared
// hairpin; a NAT that does not fails the test with its type and the
// measurement.
func TestCritNATFidelity(t *testing.T) {
	netns.Require(t)
	netns.Run(t, natFidelity)
}

func natFidelity(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Fatalf("nft is required: %v", err)
	}
	theory := loadTheory(t)
	hp, _ := realCells(theory, "hairpin")
	cg, _ := realCells(theory, "cgnat_same")
	if len(hp) != 12 || len(cg) != 32 {
		t.Fatalf("property nat-fidelity violated: theory.json has %d hairpin and %d cgnat_same cells with a real oracle, want 12 and 32", len(hp), len(cg))
	}
	eachCell(t, append(hp, cg...), func(t *testing.T, slot int, group, cell string) {
		tp := buildTopo(t, slot, group, cell)
		if err := tp.fidelity(); err != nil {
			t.Fatalf("property nat-fidelity violated: %s %s: %v", group, cell, err)
		}
	})
}

// TestCritLinuxMatrix is criterion 16: every cell with a real oracle
// (pair 28, hairpin 12, cgnat 80, cgnat_same 32) runs on nftables NATs
// with the real binaries, after the fidelity probe of its NATs, up to 4
// at once. The cell is direct if `malla wait-direct -timeout 30s` exits 0
// on both nodes, else relay. It passes if every cell matches
// matrix/theory.json or is a finding of oracle linux with that observed
// result, and no such finding names a cell that does not differ. The
// cells without a real oracle (some ADM-* type) are listed.
func TestCritLinuxMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("long: 152 cells on real NATs, up to 30 s each")
	}
	netns.Require(t)
	netns.Run(t, linuxMatrix)
}

func linuxMatrix(t *testing.T) {
	theory := loadTheory(t)
	findings := loadFindings(t, "linux")
	var cells [][2]string
	var simOnly []string
	for _, g := range groups {
		withOracle, without := realCells(theory, g)
		want := map[string]int{"pair": 28, "hairpin": 12, "cgnat": 80, "cgnat_same": 32}[g]
		if len(withOracle) != want {
			t.Fatalf("property nat-matrix violated: theory.json has %d %s cells with a real oracle, want %d", len(withOracle), g, want)
		}
		cells = append(cells, withOracle...)
		simOnly = append(simOnly, without...)
	}
	t.Logf("%d cells without a real oracle (an ADM-* type; simulator only):\n  %s", len(simOnly), strings.Join(simOnly, "\n  "))

	bin := buildBinaries(t)
	var mu sync.Mutex
	observed := make(map[string]string)
	eachCell(t, cells, func(t *testing.T, slot int, group, cell string) {
		tp := buildTopo(t, slot, group, cell)
		if err := tp.fidelity(); err != nil {
			t.Fatalf("property nat-matrix violated: %s %s: a NAT does not behave as declared: %v", group, cell, err)
		}
		m := startMesh(t, tp, bin)
		ok, err := m.waitDirect(tp)
		if err != nil {
			t.Fatalf("property nat-matrix violated: %s %s: %v", group, cell, err)
		}
		v := verdict(ok[0] && ok[1])
		t.Logf("%s %s: wait-direct a %v, b %v: %s (theory %s)", group, cell, ok[0], ok[1], v, theory[group][cell])
		mu.Lock()
		observed[group+" "+cell] = v
		mu.Unlock()
	})
	if t.Failed() {
		return
	}

	documented := make(map[string]finding)
	for _, f := range findings {
		documented[f.Group+" "+f.Cell] = f
	}
	var problems []string
	count := map[string]int{}
	for _, c := range cells {
		key := c[0] + " " + c[1]
		want, got := theory[c[0]][c[1]], observed[key]
		count[c[0]+" "+got]++
		if f, ok := documented[key]; got != want && !(ok && f.Expected == want && f.Observed == got) {
			problems = append(problems, fmt.Sprintf("%s: theory %s, observed %s", key, want, got))
		}
	}
	for _, g := range groups {
		t.Logf("%s: %d cells direct, %d relay", g, count[g+" direct"], count[g+" relay"])
	}
	for _, f := range findings {
		key := f.Group + " " + f.Cell
		want, known := theory[f.Group][f.Cell]
		switch {
		case !known:
			problems = append(problems, fmt.Sprintf("%s: listed in findings.json but not a cell of theory.json", key))
		case strings.Contains(f.Cell, "ADM-"):
			problems = append(problems, fmt.Sprintf("%s: a linux finding for a cell without a real oracle", key))
		case f.Expected != want:
			problems = append(problems, fmt.Sprintf("%s: findings.json expects %s, theory.json says %s", key, f.Expected, want))
		case observed[key] == want:
			problems = append(problems, fmt.Sprintf("%s: listed in findings.json but does not differ from the theory (%s)", key, want))
		}
	}
	if len(problems) > 0 {
		t.Fatalf("property nat-matrix violated: %d cells differ from matrix/theory.json without a matching linux finding in matrix/findings.json, or a finding is wrong:\n  %s",
			len(problems), strings.Join(problems, "\n  "))
	}
}

// symmetricTransfer is what crosses the tunnel in
// TestCritSymmetricRelayLinux.
const symmetricTransfer = 1 << 20

// TestCritSymmetricRelayLinux is criterion 18 on real NATs: a and b each
// behind an APDM-APDF nftables NAT (masquerade fully-random, conntrack
// only). Neither gets a direct path (`wait-direct -timeout 30s` exits 1
// on both), both report relay, and 1 MiB sent by TCP through the tunnel
// arrives with the same SHA-256, both still on relay.
func TestCritSymmetricRelayLinux(t *testing.T) {
	netns.Require(t)
	netns.Run(t, symmetricRelayLinux)
}

func symmetricRelayLinux(t *testing.T) {
	bin := buildBinaries(t)
	tp := buildTopo(t, 0, "pair", "APDM-APDF|APDM-APDF")
	if err := tp.fidelity(); err != nil {
		t.Fatalf("property symmetric-relay violated: a NAT does not behave as declared: %v", err)
	}
	m := startMesh(t, tp, bin)
	ok, err := m.waitDirect(tp)
	if err != nil {
		t.Fatalf("property symmetric-relay violated: %v", err)
	}
	if ok[0] || ok[1] {
		t.Fatalf("property symmetric-relay violated: wait-direct exited 0 (a %v, b %v) between two APDM-APDF NATs", ok[0], ok[1])
	}
	checkRelay := func(when string) {
		for _, s := range []struct{ ns, peer string }{{tp.a.ns, "b"}, {tp.b.ns, "a"}} {
			if p, out := m.path(s.ns, s.peer); p != "relay" {
				t.Fatalf("property symmetric-relay violated: %s, status in %s = %q, want relay for %s", when, s.ns, out, s.peer)
			}
		}
	}
	checkRelay("after wait-direct")

	data := make([]byte, symmetricTransfer)
	rand.Read(data)
	want := sha256.Sum256(data)
	dst := net.JoinHostPort(m.addr[tp.b.ns], "9001")
	var ln net.Listener
	if err := netns.Do(tp.b.ns, func() (err error) {
		ln, err = net.Listen("tcp4", dst)
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
		c.SetReadDeadline(time.Now().Add(time.Minute))
		h := sha256.New()
		var r result
		r.n, r.err = io.Copy(h, c)
		copy(r.sum[:], h.Sum(nil))
		got <- r
	}()
	var conn net.Conn
	for start := time.Now(); conn == nil; {
		if time.Since(start) > time.Minute {
			t.Fatalf("property symmetric-relay violated: no TCP connection from a to %s through the tunnel in 60 s", dst)
		}
		if err := netns.Do(tp.a.ns, func() (err error) {
			conn, err = net.DialTimeout("tcp4", dst, 3*time.Second)
			return err
		}); err != nil {
			conn = nil
			time.Sleep(200 * time.Millisecond)
		}
	}
	conn.SetWriteDeadline(time.Now().Add(time.Minute))
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("property symmetric-relay violated: write: %v", err)
	}
	conn.(*net.TCPConn).CloseWrite()
	r := <-got
	conn.Close()
	if r.err != nil || r.n != symmetricTransfer || r.sum != want {
		t.Fatalf("property symmetric-relay violated: b received %d bytes (err %v) with SHA-256 %x, want %d bytes with %x", r.n, r.err, r.sum, symmetricTransfer, want)
	}
	t.Logf("b received %d bytes with SHA-256 %x through the relay", r.n, r.sum)
	checkRelay("after the transfer")
}

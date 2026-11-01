package matrix

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/CesarManzoCode/malla-wg/internal/coord"
	"github.com/CesarManzoCode/malla-wg/internal/magic"
	"github.com/CesarManzoCode/malla-wg/sim"
)

// Parameters of the matrix in the simulator (contract §6): seeds 1..8,
// link latency uniform in [10, 50] ms, loss 0.01, direct if reached
// within 15 virtual seconds.
const (
	simDeadline int64 = 15e9
	simLoss           = 0.01
	meshPort          = 41641
	authKey           = "matrix"
)

var groups = []string{"pair", "hairpin", "cgnat", "cgnat_same"}

// Addresses of the topologies of §4.1. The coordination, with its
// reflexive service, and the relay are public hosts apart from the NATs.
var (
	coordAddr = netip.MustParseAddr("198.51.100.1")
	relayAddr = netip.MustParseAddr("198.51.100.2")
	extA      = netip.MustParseAddr("203.0.113.1") // a's NAT, the shared one, or the CGNAT
	extB      = netip.MustParseAddr("203.0.113.2") // b's own NAT
	publicA   = netip.MustParseAddr("203.0.113.101")
	publicB   = netip.MustParseAddr("203.0.113.102")
	localA    = netip.MustParseAddr("192.168.1.2")
	localB    = netip.MustParseAddr("192.168.2.2")
	homeA     = netip.MustParseAddr("100.64.0.1") // home NATs inside the CGNAT (RFC 6598)
	homeB     = netip.MustParseAddr("100.64.0.2")
)

// unroutable drops every datagram sent to a local address of the peers:
// local addresses are not routable between them, and the inside segments
// of one NAT are not routed to each other (§4.1). It runs before the
// NATs, so it sees the destination as sent, not as a NAT rewrote it.
type unroutable map[netip.Addr]bool

func (u unroutable) Process(_ int64, _ *sim.Host, p *sim.Packet) string {
	if u[p.Dst.Addr()] {
		return sim.DropNoRoute
	}
	return ""
}

func natConfig(t string, hairpin bool) sim.NATConfig {
	m, f, err := sim.ParseNATType(t)
	if err != nil {
		panic(err)
	}
	return sim.NATConfig{Mapping: m, Filtering: f, Hairpin: hairpin}
}

// world is one run of a cell: mesh nodes a and b with the coordination
// and the relay. direct records that both reported a direct path to the
// other at the same instant.
type world struct {
	s      *sim.Sim
	a, b   *sim.MeshNode
	direct bool
}

// newWorld builds the topology of a cell of §4.3 with seed:
//
//   - pair "<a>|<b>": each node behind its own NAT, or public for none;
//   - hairpin "<t>|hairpin=<bool>": both behind one NAT, in two inside
//     segments;
//   - cgnat "<h>><c>|<b>": a behind home NAT h inside CGNAT c, b behind
//     its own NAT or public;
//   - cgnat_same "<h>><c>|hairpin=<bool>": each behind its home NAT h,
//     both inside one CGNAT c, which has hairpin or not.
func newWorld(group, cell string, seed uint64) (*world, error) {
	s := sim.New(seed, nil)
	rnd := rand.New(s.Stream())
	left, right, _ := strings.Cut(cell, "|")
	hairpin := right == "hairpin=True"
	addrA, addrB := localA, localB
	if group == "pair" && left == "none" {
		addrA = publicA
	}
	if (group == "pair" || group == "cgnat") && right == "none" {
		addrB = publicB
	}
	hc, hr := s.NewHost("coord", coordAddr), s.NewHost("relay", relayAddr)
	ha, hb := s.NewHost("a", addrA), s.NewHost("b", addrB)
	s.AddMiddlebox(unroutable{localA: true, localB: true})
	switch group {
	case "pair":
		if addrA == localA {
			s.NewNAT("nat-a", extA, natConfig(left, false)).Add(ha)
		}
		if addrB == localB {
			s.NewNAT("nat-b", extB, natConfig(right, false)).Add(hb)
		}
	case "hairpin":
		s.NewNAT("nat", extA, natConfig(left, hairpin)).Add(ha, hb)
	case "cgnat", "cgnat_same":
		h, c, _ := strings.Cut(left, ">")
		cg := s.NewNAT("cgnat", extA, natConfig(c, group == "cgnat_same" && hairpin))
		cg.NewNAT("home-a", homeA, natConfig(h, false)).Add(ha)
		switch {
		case group == "cgnat_same":
			cg.NewNAT("home-b", homeB, natConfig(h, false)).Add(hb)
		case addrB == localB:
			s.NewNAT("nat-b", extB, natConfig(right, false)).Add(hb)
		}
	default:
		return nil, fmt.Errorf("unknown group %q", group)
	}
	link := func(x, y *sim.Host, loss float64) {
		s.Connect(x, y, sim.LinkConfig{Latency: (10 + rnd.Int64N(41)) * sim.Ms, Loss: loss})
	}
	link(ha, hb, simLoss)
	link(ha, hc, simLoss)
	link(hb, hc, simLoss)
	link(ha, hr, 0) // the relay's channels are reliable; only their latency counts
	link(hb, hr, 0)
	c, err := s.NewCoord(hc, coord.CoreConfig{AuthKeys: []string{authKey}, Relay: "sim",
		Policy: &coord.Policy{Rules: []coord.Rule{{Src: []string{"a"}, Dst: []string{"b"}}}}})
	if err != nil {
		return nil, err
	}
	r := s.NewRelay(hr)
	w := &world{s: s}
	if w.a, err = sim.AttachMesh(ha, sim.MeshConfig{Name: "a", Port: meshPort, AuthKey: authKey, Coord: c, Relay: r}); err != nil {
		return nil, err
	}
	if w.b, err = sim.AttachMesh(hb, sim.MeshConfig{Name: "b", Port: meshPort, AuthKey: authKey, Coord: c, Relay: r}); err != nil {
		return nil, err
	}
	check := func() {
		if w.a.Path(w.b) == magic.PathDirect && w.b.Path(w.a) == magic.PathDirect {
			w.direct = true
		}
	}
	w.a.OnPath, w.b.OnPath = check, check
	return w, nil
}

// runCell runs a cell with seed for 15 virtual seconds and returns its
// result: direct if both nodes reported a direct path, else relay.
func runCell(group, cell string, seed uint64) (string, error) {
	w, err := newWorld(group, cell, seed)
	if err != nil {
		return "", err
	}
	if err := w.s.RunUntil(simDeadline); err != nil {
		return "", err
	}
	return verdict(w.direct), nil
}

func loadTheory(t *testing.T) map[string]map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../../matrix/theory.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Groups map[string]map[string]string `json:"groups"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("theory.json: %v", err)
	}
	return file.Groups
}

// finding is one entry of matrix/findings.json (§4.5).
type finding struct {
	Group       string `json:"group"`
	Cell        string `json:"cell"`
	Oracle      string `json:"oracle"`
	Expected    string `json:"expected"`
	Observed    string `json:"observed"`
	Kind        string `json:"kind"`
	Explanation string `json:"explanation"`
	Seed        uint64 `json:"seed"`
}

// loadFindings reads matrix/findings.json and returns its entries of
// oracle, failing on a file that does not follow §4.5.
func loadFindings(t *testing.T, oracle string) []finding {
	t.Helper()
	raw, err := os.ReadFile("../../matrix/findings.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Format   string    `json:"format"`
		Findings []finding `json:"findings"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil || file.Format != "malla-nat-findings/1" || file.Findings == nil {
		t.Fatalf("property nat-matrix violated: matrix/findings.json is not malla-nat-findings/1 with a findings list (%v)", err)
	}
	var out []finding
	for i, f := range file.Findings {
		if !slices.Contains(groups, f.Group) || (f.Oracle != "sim" && f.Oracle != "linux") ||
			(f.Kind != "bug" && f.Kind != "hallazgo") || f.Explanation == "" {
			t.Fatalf("property nat-matrix violated: matrix/findings.json entry %d (%s %s) lacks a valid group, oracle, kind or explanation", i, f.Group, f.Cell)
		}
		if f.Oracle == oracle {
			out = append(out, f)
		}
	}
	return out
}

// sortedCells returns the cells of a group in order.
func sortedCells(cells map[string]string) []string {
	keys := make([]string, 0, len(cells))
	for k := range cells {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// TestCritSimMatrix is criterion 15: every cell of matrix/theory.json runs
// in the simulator with seeds 1..8. A cell differs if some seed gives
// another result than the theory; the test passes if every differing cell
// is a finding of oracle sim with that observed result and no such
// finding names a cell that does not differ. With -sim.seed only that
// seed runs, and only the findings recorded with it must still differ.
func TestCritSimMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("long: 185 cells with 8 seeds each")
	}
	theory := loadTheory(t)
	findings := loadFindings(t, "sim")
	type job struct {
		group, cell string
		seed        uint64
	}
	var jobs []job
	for _, g := range groups {
		for _, cell := range sortedCells(theory[g]) {
			for _, seed := range sim.Seeds(1, 8) {
				jobs = append(jobs, job{g, cell, seed})
			}
		}
	}
	results, errs := make([]string, len(jobs)), make([]error, len(jobs))
	next := make(chan int)
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				results[i], errs[i] = runCell(jobs[i].group, jobs[i].cell, jobs[i].seed)
			}
		}()
	}
	for i := range jobs {
		next <- i
	}
	close(next)
	wg.Wait()

	// differs maps "group cell" to the seeds whose result is not the
	// theory's; with two outcomes the observed result is the other one.
	differs := make(map[string][]uint64)
	var order []string
	observed := make(map[string]int)
	for i, j := range jobs {
		if errs[i] != nil {
			sim.Fatal(t, j.seed, "property nat-matrix violated: %s %s did not run: %v", j.group, j.cell, errs[i])
		}
		observed[j.group+" "+results[i]]++
		if results[i] != theory[j.group][j.cell] {
			key := j.group + " " + j.cell
			if differs[key] == nil {
				order = append(order, key)
			}
			differs[key] = append(differs[key], j.seed)
		}
	}
	for _, g := range groups {
		t.Logf("%s: %d runs direct, %d relay", g, observed[g+" direct"], observed[g+" relay"])
	}
	other := map[string]string{"direct": "relay", "relay": "direct"}
	documented := make(map[string]finding)
	for _, f := range findings {
		documented[f.Group+" "+f.Cell] = f
	}
	var problems []string
	for _, key := range order {
		g, cell, _ := strings.Cut(key, " ")
		want := theory[g][cell]
		seeds := differs[key]
		if f, ok := documented[key]; ok && f.Expected == want && f.Observed == other[want] {
			continue
		}
		problems = append(problems, fmt.Sprintf("%s %s: theory %s, observed %s with seeds %v\n    seed=%d\n    repro: %s",
			g, cell, want, other[want], seeds, seeds[0], sim.ReproCommand(t, seeds[0])))
	}
	flagSeed, only := sim.SeedFlag()
	for _, f := range findings {
		key := f.Group + " " + f.Cell
		want, known := theory[f.Group][f.Cell]
		switch {
		case !known:
			problems = append(problems, fmt.Sprintf("%s %s: listed in findings.json but not a cell of theory.json", f.Group, f.Cell))
		case f.Expected != want:
			problems = append(problems, fmt.Sprintf("%s %s: findings.json expects %s, theory.json says %s", f.Group, f.Cell, f.Expected, want))
		case differs[key] == nil && (!only || f.Seed == flagSeed):
			problems = append(problems, fmt.Sprintf("%s %s: listed in findings.json but does not differ from the theory (%s)\n    seed=%d\n    repro: %s",
				f.Group, f.Cell, want, f.Seed, sim.ReproCommand(t, f.Seed)))
		}
	}
	if len(problems) > 0 {
		t.Fatalf("property nat-matrix violated: %d cells differ from matrix/theory.json without a matching finding in matrix/findings.json, or a finding is wrong:\n  %s",
			len(problems), strings.Join(problems, "\n  "))
	}
}

// symmetricCount is how many datagrams cross the tunnel in
// TestCritSymmetricRelaySim.
const symmetricCount = 100

// TestCritSymmetricRelaySim is criterion 18 in the simulator: in the pair
// cells where neither side maps independently of the endpoint and the
// theory says relay, both nodes report relay at 15 s, and 100 datagrams
// sent through the tunnel afterwards all arrive, with both still on relay.
func TestCritSymmetricRelaySim(t *testing.T) {
	theory := loadTheory(t)
	var cells []string
	for _, cell := range sortedCells(theory["pair"]) {
		a, b, _ := strings.Cut(cell, "|")
		ma, _ := behaviors(a)
		mb, _ := behaviors(b)
		if ma != "EIM" && mb != "EIM" && theory["pair"][cell] == "relay" {
			cells = append(cells, cell)
		}
	}
	if len(cells) == 0 {
		t.Fatal("theory.json has no pair cell with both sides non-EIM and relay")
	}
	for _, seed := range sim.Seeds(1, 8) {
		for _, cell := range cells {
			if msg := symmetricRun(cell, seed); msg != "" {
				sim.Fatal(t, seed, "property symmetric-relay violated: pair %s: %s", cell, msg)
			}
		}
	}
}

// symmetricRun runs one cell for TestCritSymmetricRelaySim and describes
// what went wrong, or returns "".
func symmetricRun(cell string, seed uint64) string {
	w, err := newWorld("pair", cell, seed)
	if err != nil {
		return err.Error()
	}
	if err := w.s.RunUntil(simDeadline); err != nil {
		return err.Error()
	}
	if pa, pb := w.a.Path(w.b), w.b.Path(w.a); pa != magic.PathRelay || pb != magic.PathRelay {
		return fmt.Sprintf("at 15 s a reports %v and b reports %v, want relay on both", pa, pb)
	}
	got := make(map[uint64]bool)
	w.b.OnTUN = func(pkt []byte) {
		if len(pkt) == 20+4+8 && string(pkt[20:24]) == "symm" {
			got[binary.BigEndian.Uint64(pkt[24:])] = true
		}
	}
	for i := range uint64(symmetricCount) {
		payload := binary.BigEndian.AppendUint64([]byte("symm"), i)
		w.s.At(simDeadline+int64(i)*10*sim.Ms, func() {
			w.a.Inject(sim.IPv4Packet(w.a.Addr(), w.b.Addr(), payload))
		})
	}
	if err := w.s.RunUntil(simDeadline + 6e9); err != nil {
		return err.Error()
	}
	if len(got) != symmetricCount {
		return fmt.Sprintf("b received %d of %d datagrams sent through the tunnel", len(got), symmetricCount)
	}
	if pa, pb := w.a.Path(w.b), w.b.Path(w.a); pa != magic.PathRelay || pb != magic.PathRelay {
		return fmt.Sprintf("after the transfer a reports %v and b reports %v, want relay on both", pa, pb)
	}
	return ""
}

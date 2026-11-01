package matrix

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// natTypes is the type list of the contract §4.3, in its order.
var natTypes = strings.Fields("none EIM-EIF EIM-ADF EIM-APDF ADM-EIF ADM-ADF ADM-APDF APDM-EIF APDM-ADF APDM-APDF")

// behaviors splits a type into its mapping and filtering; "none" is a
// public host, EIM-EIF without translation.
func behaviors(t string) (mapping, filtering string) {
	if t == "none" {
		return "EIM", "EIF"
	}
	mapping, filtering, _ = strings.Cut(t, "-")
	return mapping, filtering
}

// direct is rule 1 of §4.2 for the pair a|b.
func direct(a, b string) bool {
	ma, fa := behaviors(a)
	mb, fb := behaviors(b)
	switch {
	case ma == "EIM" && mb == "EIM":
		return true
	case ma == "EIM":
		return fa != "APDF"
	case mb == "EIM":
		return fb != "APDF"
	}
	return fa == "EIF" && fb != "APDF" || fb == "EIF" && fa != "APDF"
}

// stricter returns the more restrictive of two behaviors of one order.
func stricter(order []string, x, y string) string {
	for _, b := range order {
		if b == x || b == y {
			if b == x {
				return y
			}
			return x
		}
	}
	return x
}

// composed is rule 3 of §4.2: home NAT h inside CGNAT c as one NAT.
func composed(h, c string) string {
	mh, fh := behaviors(h)
	mc, fc := behaviors(c)
	return stricter([]string{"EIM", "ADM", "APDM"}, mh, mc) + "-" + stricter([]string{"EIF", "ADF", "APDF"}, fh, fc)
}

func verdict(ok bool) string {
	if ok {
		return "direct"
	}
	return "relay"
}

// expectedTheory recomputes the four groups of §4.3 with the rules of §4.2.
func expectedTheory() map[string]map[string]string {
	g := map[string]map[string]string{"pair": {}, "hairpin": {}, "cgnat": {}, "cgnat_same": {}}
	for i, a := range natTypes {
		for _, b := range natTypes[i:] {
			g["pair"][a+"|"+b] = verdict(direct(a, b))
		}
	}
	for _, t := range natTypes[1:] {
		g["hairpin"][t+"|hairpin=True"] = verdict(direct(t, t)) // rule 2
		g["hairpin"][t+"|hairpin=False"] = "relay"
	}
	cg := []string{"EIM-EIF", "EIM-ADF", "EIM-APDF", "APDM-APDF"}
	for _, h := range cg {
		for _, c := range cg {
			hc := composed(h, c)
			for _, b := range append([]string{"none"}, cg...) {
				g["cgnat"][h+">"+c+"|"+b] = verdict(direct(hc, b))
			}
			g["cgnat_same"][h+">"+c+"|hairpin=True"] = verdict(direct(hc, hc))
			g["cgnat_same"][h+">"+c+"|hairpin=False"] = "relay"
		}
	}
	return g
}

// TestCritTheoryCoverage is criterion 14: matrix/theory.json has the
// format of §4.3, exactly the 185 cells of the four groups, the counts of
// direct cells of §4.3 and, in every cell, the value of the rules of §4.2.
func TestCritTheoryCoverage(t *testing.T) {
	raw, err := os.ReadFile("../../matrix/theory.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Format string                       `json:"format"`
		Source string                       `json:"source"`
		Groups map[string]map[string]string `json:"groups"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		t.Fatalf("theory.json: %v", err)
	}
	if file.Format != "malla-nat-theory/1" || file.Source != "RFC 4787" {
		t.Fatalf("format %q source %q, want malla-nat-theory/1 and RFC 4787", file.Format, file.Source)
	}
	want := expectedTheory()
	sizes := map[string][2]int{"pair": {55, 35}, "hairpin": {18, 5}, "cgnat": {80, 61}, "cgnat_same": {32, 9}}
	if len(file.Groups) != len(sizes) {
		t.Errorf("theory.json has %d groups, want %d", len(file.Groups), len(sizes))
	}
	total := 0
	for _, name := range []string{"pair", "hairpin", "cgnat", "cgnat_same"} {
		exp, got := want[name], file.Groups[name]
		if n, d := len(exp), countDirect(exp); n != sizes[name][0] || d != sizes[name][1] {
			t.Fatalf("rules give %s %d cells, %d direct; the contract says %d and %d", name, n, d, sizes[name][0], sizes[name][1])
		}
		if n, d := len(got), countDirect(got); n != sizes[name][0] || d != sizes[name][1] {
			t.Errorf("theory.json %s: %d cells, %d direct; want %d and %d", name, n, d, sizes[name][0], sizes[name][1])
		}
		for cell, v := range exp {
			if g, ok := got[cell]; !ok {
				t.Errorf("%s: cell %q missing", name, cell)
			} else if g != v {
				t.Errorf("%s: cell %q is %q, the rules give %q", name, cell, g, v)
			}
		}
		for cell := range got {
			if _, ok := exp[cell]; !ok {
				t.Errorf("%s: unexpected cell %q", name, cell)
			}
		}
		total += len(got)
	}
	if total != 185 {
		t.Errorf("theory.json has %d cells, want 185", total)
	}
}

func countDirect(cells map[string]string) int {
	n := 0
	for _, v := range cells {
		if v == "direct" {
			n++
		}
	}
	return n
}

// Command gentheory writes matrix/theory.json, the theoretical NAT table of
// the contract §4.3, by applying the closed rules of §4.2 to every cell.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

// types is the list of §4.3, in its order.
var types = []string{"none", "EIM-EIF", "EIM-ADF", "EIM-APDF", "ADM-EIF", "ADM-ADF",
	"ADM-APDF", "APDM-EIF", "APDM-ADF", "APDM-APDF"}

// cgnatTypes are the home and carrier NAT types of the cgnat groups.
var cgnatTypes = []string{"EIM-EIF", "EIM-ADF", "EIM-APDF", "APDM-APDF"}

// nat is a NAT type as ranks: mapping EIM < ADM < APDM and filtering
// EIF < ADF < APDF, both from 0. "none" is EIM-EIF.
type nat struct{ m, f int }

func parse(t string) nat {
	if t == "none" {
		return nat{}
	}
	m, f, _ := strings.Cut(t, "-")
	return nat{rank(m, "EIM", "ADM", "APDM"), rank(f, "EIF", "ADF", "APDF")}
}

func rank(s string, names ...string) int {
	for i, n := range names {
		if s == n {
			return i
		}
	}
	panic("gentheory: unknown NAT behavior " + s)
}

// pair is rule 1 of §4.2.
func pair(a, b nat) string {
	const apdf = 2
	ea, eb := a.m == 0, b.m == 0
	var ok bool
	switch {
	case ea && eb:
		ok = true
	case ea:
		ok = a.f != apdf
	case eb:
		ok = b.f != apdf
	default:
		ok = (a.f == 0 && b.f != apdf) || (b.f == 0 && a.f != apdf)
	}
	if ok {
		return "direct"
	}
	return "relay"
}

// hairpin is rule 2 of §4.2.
func hairpin(t nat, on bool) string {
	if !on {
		return "relay"
	}
	return pair(t, t)
}

// compose is rule 3 of §4.2.
func compose(h, c nat) nat { return nat{max(h.m, c.m), max(h.f, c.f)} }

type theory struct {
	Format string `json:"format"`
	Source string `json:"source"`
	Groups struct {
		Pair      map[string]string `json:"pair"`
		Hairpin   map[string]string `json:"hairpin"`
		CGNAT     map[string]string `json:"cgnat"`
		CGNATSame map[string]string `json:"cgnat_same"`
	} `json:"groups"`
}

func build() theory {
	th := theory{Format: "malla-nat-theory/1", Source: "RFC 4787"}
	g := &th.Groups
	g.Pair, g.Hairpin = map[string]string{}, map[string]string{}
	g.CGNAT, g.CGNATSame = map[string]string{}, map[string]string{}
	for i, a := range types {
		for _, b := range types[i:] {
			g.Pair[a+"|"+b] = pair(parse(a), parse(b))
		}
	}
	for _, t := range types[1:] {
		for _, on := range []bool{true, false} {
			g.Hairpin[fmt.Sprintf("%s|hairpin=%s", t, pyBool(on))] = hairpin(parse(t), on)
		}
	}
	for _, h := range cgnatTypes {
		for _, c := range cgnatTypes {
			hc := compose(parse(h), parse(c))
			for _, b := range append([]string{"none"}, cgnatTypes...) {
				g.CGNAT[h+">"+c+"|"+b] = pair(hc, parse(b))
			}
			for _, on := range []bool{true, false} {
				g.CGNATSame[fmt.Sprintf("%s>%s|hairpin=%s", h, c, pyBool(on))] = hairpin(hc, on)
			}
		}
	}
	return th
}

// pyBool spells a boolean as the keys of §4.3 do.
func pyBool(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

func main() {
	out := flag.String("o", "matrix/theory.json", "output file")
	flag.Parse()
	b, err := json.MarshalIndent(build(), "", "  ")
	if err == nil {
		err = os.WriteFile(*out, append(b, '\n'), 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gentheory:", err)
		os.Exit(1)
	}
}

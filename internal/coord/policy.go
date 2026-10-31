package coord

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Policy is the access policy of contract §3.1: groups of node names and
// symmetric rules. A pair of nodes may talk only if some rule allows it.
type Policy struct {
	Groups map[string][]string `json:"groups"`
	Rules  []Rule              `json:"rules"`
}

// Rule allows every node matched by Src to talk with every node matched by
// Dst, in both directions. A selector is a node name, "tag:<t>" or
// "group:<g>".
type Rule struct {
	Src []string `json:"src"`
	Dst []string `json:"dst"`
}

// Member is what a selector looks at: the node's name and tags (without
// the "tag:" prefix).
type Member struct {
	Name string
	Tags []string
}

// Validate checks group names and that every "group:" selector names a
// defined group.
func (p *Policy) Validate() error {
	names := make([]string, 0, len(p.Groups))
	for g := range p.Groups {
		names = append(names, g)
	}
	sort.Strings(names)
	for _, g := range names {
		if !strings.HasPrefix(g, "group:") || len(g) == len("group:") {
			return fmt.Errorf("%w: group %q must be group:<name>", ErrBadRequest, g)
		}
	}
	for i, r := range p.Rules {
		if len(r.Src) == 0 || len(r.Dst) == 0 {
			return fmt.Errorf("%w: rule %d needs src and dst", ErrBadRequest, i)
		}
		for _, sel := range slices.Concat(r.Src, r.Dst) {
			if err := p.checkSelector(sel); err != nil {
				return fmt.Errorf("%w: rule %d: %v", ErrBadRequest, i, err)
			}
		}
	}
	return nil
}

func (p *Policy) checkSelector(sel string) error {
	switch {
	case sel == "", sel == "tag:", sel == "group:":
		return fmt.Errorf("empty selector %q", sel)
	case strings.HasPrefix(sel, "group:"):
		if _, ok := p.Groups[sel]; !ok {
			return fmt.Errorf("undefined group %q", sel)
		}
	}
	return nil
}

// Allows reports whether a and b may talk. It denies by default and never
// pairs a node with itself.
func (p *Policy) Allows(a, b Member) bool {
	if p == nil || a.Name == b.Name {
		return false
	}
	for _, r := range p.Rules {
		if p.anyMatch(r.Src, a) && p.anyMatch(r.Dst, b) || p.anyMatch(r.Src, b) && p.anyMatch(r.Dst, a) {
			return true
		}
	}
	return false
}

func (p *Policy) anyMatch(sels []string, m Member) bool {
	for _, sel := range sels {
		if p.match(sel, m) {
			return true
		}
	}
	return false
}

func (p *Policy) match(sel string, m Member) bool {
	if t, ok := strings.CutPrefix(sel, "tag:"); ok {
		return slices.Contains(m.Tags, t)
	}
	if strings.HasPrefix(sel, "group:") {
		return slices.Contains(p.Groups[sel], m.Name)
	}
	return sel == m.Name
}

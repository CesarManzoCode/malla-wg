package coord

import (
	"bytes"
	"errors"
	"testing"
)

func TestPolicySelectors(t *testing.T) {
	p := &Policy{
		Groups: map[string][]string{"group:ops": {"alice", "bob"}},
		Rules: []Rule{
			{Src: []string{"web1"}, Dst: []string{"db1"}},
			{Src: []string{"tag:ci"}, Dst: []string{"tag:build"}},
			{Src: []string{"group:ops"}, Dst: []string{"tag:server"}},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	m := func(name string, tags ...string) Member { return Member{Name: name, Tags: tags} }
	for _, tc := range []struct {
		a, b Member
		want bool
	}{
		{m("web1"), m("db1"), true},
		{m("db1"), m("web1"), true}, // a rule allows both directions
		{m("web1"), m("db2"), false},
		{m("web2"), m("db1"), false},
		{m("runner", "ci"), m("builder", "build"), true},
		{m("builder", "build"), m("runner", "ci"), true},
		{m("runner", "ci"), m("other", "ci"), false},
		{m("alice"), m("s1", "server"), true},
		{m("s1", "server"), m("bob"), true},
		{m("carol"), m("s1", "server"), false},
		{m("alice"), m("bob"), false},             // same group, no rule between them
		{m("web1"), m("web1"), false},             // never with itself
		{m("x", "ops"), m("s1", "server"), false}, // a tag is not a group
	} {
		if got := p.Allows(tc.a, tc.b); got != tc.want {
			t.Errorf("Allows(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestPolicyDenyByDefault(t *testing.T) {
	a, b := Member{Name: "a"}, Member{Name: "b"}
	var nilPolicy *Policy
	for name, p := range map[string]*Policy{"nil": nilPolicy, "empty": {}, "no-match": {Rules: []Rule{{Src: []string{"c"}, Dst: []string{"d"}}}}} {
		if p.Allows(a, b) {
			t.Errorf("%s policy allows a and b", name)
		}
	}
}

func TestPolicyValidate(t *testing.T) {
	for name, p := range map[string]Policy{
		"undefined group": {Rules: []Rule{{Src: []string{"group:x"}, Dst: []string{"a"}}}},
		"bad group name":  {Groups: map[string][]string{"ops": {"a"}}},
		"empty selector":  {Rules: []Rule{{Src: []string{"tag:"}, Dst: []string{"a"}}}},
		"empty dst":       {Rules: []Rule{{Src: []string{"a"}}}},
	} {
		if err := p.Validate(); !errors.Is(err, ErrBadRequest) {
			t.Errorf("%s: Validate = %v, want ErrBadRequest", name, err)
		}
	}
}

// TestCoreMapFollowsPolicy checks that the map only lists allowed peers
// and that revocation removes the node, its token and its key for good.
func TestCoreMapFollowsPolicy(t *testing.T) {
	c, err := NewCore(CoreConfig{
		AuthKeys: []string{"k"}, AdminToken: "admin",
		Policy: &Policy{Rules: []Rule{{Src: []string{"a"}, Dst: []string{"b"}}}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rnd := bytes.NewReader(bytes.Repeat([]byte{1, 2, 3, 4, 5, 6, 7}, 100))
	reg := map[string]RegisterResponse{}
	for i, name := range []string{"a", "b", "c"} {
		resp, err := c.Register(RegisterRequest{AuthKey: "k", NodeKey: Key{byte(i + 1)}, Name: name}, rnd)
		if err != nil {
			t.Fatal(err)
		}
		reg[name] = resp
	}
	if _, err := c.Register(RegisterRequest{AuthKey: "bad", NodeKey: Key{9}, Name: "d"}, rnd); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("register with a wrong auth key: %v", err)
	}
	peers := func(name string) []string {
		nm, err := c.Netmap(reg[name].Token)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, p := range nm.Peers {
			names = append(names, p.Name)
		}
		return names
	}
	if got := peers("a"); len(got) != 1 || got[0] != "b" {
		t.Fatalf("map of a = %v, want [b]", got)
	}
	if got := peers("c"); len(got) != 0 {
		t.Fatalf("map of c = %v, want none", got)
	}
	if err := c.Revoke("wrong", reg["b"].NodeID); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoke with a wrong admin token: %v", err)
	}
	if err := c.Revoke("admin", reg["b"].NodeID); err != nil {
		t.Fatal(err)
	}
	if got := peers("a"); len(got) != 0 {
		t.Fatalf("map of a after revoking b = %v, want none", got)
	}
	if _, err := c.Netmap(reg["b"].Token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("netmap with the revoked token: %v", err)
	}
	if _, err := c.Register(RegisterRequest{AuthKey: "k", NodeKey: Key{2}, Name: "b2"}, rnd); !errors.Is(err, ErrForbidden) {
		t.Fatalf("register with the revoked key: %v", err)
	}
	saved, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := NewCore(CoreConfig{AuthKeys: []string{"k"}}, saved)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Register(RegisterRequest{AuthKey: "k", NodeKey: Key{2}, Name: "b"}, rnd); !errors.Is(err, ErrForbidden) {
		t.Fatalf("register with the revoked key after reload: %v", err)
	}
}

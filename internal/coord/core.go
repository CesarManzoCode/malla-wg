package coord

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
)

// MaxEndpoints bounds the endpoints a node may report.
const MaxEndpoints = 16

// meshPrefix is where node addresses come from (D18): node n gets
// 10.200.0.0 + n, so the first is 10.200.0.1 and the last 10.200.255.254.
var meshPrefix = netip.MustParsePrefix("10.200.0.0/16")

// MeshPrefix is the prefix of the mesh's addresses (D18). They live on
// the TUNs, so they are never endpoints of the underlying network.
var MeshPrefix = meshPrefix

const maxNodeID = 1<<16 - 2

// CoreConfig is what Core needs besides its saved state.
type CoreConfig struct {
	AuthKeys   []string
	AdminToken string
	// Policy is used only when the saved state has none: a policy set
	// through PUT /v1/admin/policy is persisted and wins over it.
	Policy *Policy
	Relay  string
}

// Core is the coordination's state and rules. It reads no clock, opens no
// socket and starts no goroutine; randomness comes from the caller. It is
// not safe for concurrent use.
type Core struct {
	authKeys   []string
	adminToken string
	relay      string
	st         savedState
	byToken    map[string]*nodeRecord // token hash → node
}

// savedState is state.json.
type savedState struct {
	Version uint64        `json:"version"`
	LastID  uint64        `json:"last_id"`
	Nodes   []*nodeRecord `json:"nodes"` // node_id order
	Revoked []Key         `json:"revoked_keys"`
	Policy  *Policy       `json:"policy"`
}

type nodeRecord struct {
	ID        uint64     `json:"node_id"`
	Name      string     `json:"name"`
	NodeKey   Key        `json:"node_key"`
	DiscoKey  Key        `json:"disco_key"`
	Tags      []string   `json:"tags"`
	Addr      netip.Addr `json:"addr"`
	Endpoints []string   `json:"endpoints"`
	TokenHash string     `json:"token_sha256"`
}

// NewCore returns the coordination of cfg over the state saved by
// Marshal, or a fresh one if saved is empty.
func NewCore(cfg CoreConfig, saved []byte) (*Core, error) {
	c := &Core{
		authKeys:   cfg.AuthKeys,
		adminToken: cfg.AdminToken,
		relay:      cfg.Relay,
		byToken:    make(map[string]*nodeRecord),
	}
	if len(saved) > 0 {
		if err := json.Unmarshal(saved, &c.st); err != nil {
			return nil, fmt.Errorf("coord: saved state: %w", err)
		}
	}
	if c.st.Policy == nil && cfg.Policy != nil {
		if err := cfg.Policy.Validate(); err != nil {
			return nil, fmt.Errorf("coord: policy: %w", err)
		}
		c.st.Policy = cfg.Policy
	}
	for _, n := range c.st.Nodes {
		c.byToken[n.TokenHash] = n
	}
	return c, nil
}

// Marshal returns the state to persist.
func (c *Core) Marshal() ([]byte, error) { return json.MarshalIndent(&c.st, "", "  ") }

// Version is the map's version; every change raises it.
func (c *Core) Version() uint64 { return c.st.Version }

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (c *Core) node(token string) (*nodeRecord, error) {
	if n := c.byToken[hashToken(token)]; n != nil && token != "" {
		return n, nil
	}
	return nil, ErrUnauthorized
}

func (c *Core) checkAdmin(token string) error {
	if c.adminToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(c.adminToken)) != 1 {
		return ErrUnauthorized
	}
	return nil
}

func validName(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// Register admits a node with a valid auth key. A key already registered
// keeps its node_id and address and gets a fresh token, which replaces the
// old one; a revoked key is refused for good.
func (c *Core) Register(req RegisterRequest, rnd io.Reader) (RegisterResponse, error) {
	ok := false
	for _, k := range c.authKeys {
		if subtle.ConstantTimeCompare([]byte(req.AuthKey), []byte(k)) == 1 && k != "" {
			ok = true
		}
	}
	if !ok {
		return RegisterResponse{}, ErrUnauthorized
	}
	if req.NodeKey == (Key{}) {
		return RegisterResponse{}, fmt.Errorf("%w: node_key is zero", ErrBadRequest)
	}
	if slices.Contains(c.st.Revoked, req.NodeKey) {
		return RegisterResponse{}, fmt.Errorf("%w: node key revoked", ErrForbidden)
	}
	if !validName(req.Name) {
		return RegisterResponse{}, fmt.Errorf("%w: invalid name %q", ErrBadRequest, req.Name)
	}
	tags := make([]string, 0, len(req.Tags))
	for _, t := range req.Tags {
		t = strings.TrimPrefix(t, "tag:")
		if !validName(t) {
			return RegisterResponse{}, fmt.Errorf("%w: invalid tag %q", ErrBadRequest, t)
		}
		tags = append(tags, t)
	}
	var self *nodeRecord
	for _, n := range c.st.Nodes {
		switch {
		case n.NodeKey == req.NodeKey:
			self = n
		case n.Name == req.Name:
			return RegisterResponse{}, fmt.Errorf("%w: name %q is taken", ErrConflict, req.Name)
		}
	}
	var raw [32]byte
	if _, err := io.ReadFull(rnd, raw[:]); err != nil {
		return RegisterResponse{}, err
	}
	token := hex.EncodeToString(raw[:])
	if self == nil {
		if c.st.LastID >= maxNodeID {
			return RegisterResponse{}, ErrFull
		}
		c.st.LastID++
		a := meshPrefix.Addr().As4()
		a[2], a[3] = byte(c.st.LastID>>8), byte(c.st.LastID)
		self = &nodeRecord{ID: c.st.LastID, Addr: netip.AddrFrom4(a), NodeKey: req.NodeKey}
		c.st.Nodes = append(c.st.Nodes, self)
	} else {
		delete(c.byToken, self.TokenHash)
	}
	self.Name, self.DiscoKey, self.Tags = req.Name, req.DiscoKey, tags
	self.TokenHash = hashToken(token)
	c.byToken[self.TokenHash] = self
	c.st.Version++
	return RegisterResponse{NodeID: self.ID, Token: token, Addr: self.Addr}, nil
}

func (n *nodeRecord) view() Node {
	return Node{
		NodeID: n.ID, Name: n.Name, NodeKey: n.NodeKey, DiscoKey: n.DiscoKey,
		Addr: n.Addr, Endpoints: slices.Clone(n.Endpoints),
	}
}

func (n *nodeRecord) member() Member { return Member{Name: n.Name, Tags: n.Tags} }

// Netmap returns the map of the node with token: itself and the peers the
// policy allows, in node_id order.
func (c *Core) Netmap(token string) (Netmap, error) {
	self, err := c.node(token)
	if err != nil {
		return Netmap{}, err
	}
	nm := Netmap{Version: c.st.Version, Self: self.view(), Peers: []Node{}, Relay: c.relay}
	for _, n := range c.st.Nodes {
		if n != self && c.st.Policy.Allows(self.member(), n.member()) {
			nm.Peers = append(nm.Peers, n.view())
		}
	}
	return nm, nil
}

// SetEndpoints replaces the endpoints of the node with token.
func (c *Core) SetEndpoints(token string, eps []string) error {
	self, err := c.node(token)
	if err != nil {
		return err
	}
	if len(eps) > MaxEndpoints {
		return fmt.Errorf("%w: more than %d endpoints", ErrBadRequest, MaxEndpoints)
	}
	clean := make([]string, 0, len(eps))
	for _, e := range eps {
		ap, err := netip.ParseAddrPort(e)
		if err != nil || ap.Port() == 0 {
			return fmt.Errorf("%w: endpoint %q", ErrBadRequest, e)
		}
		clean = append(clean, ap.String())
	}
	self.Endpoints = clean
	c.st.Version++
	return nil
}

// SetPolicy replaces the policy.
func (c *Core) SetPolicy(admin string, p Policy) error {
	if err := c.checkAdmin(admin); err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return err
	}
	c.st.Policy = &p
	c.st.Version++
	return nil
}

// Revoke removes node id from every map, invalidates its token and blocks
// its key from registering again.
func (c *Core) Revoke(admin string, id uint64) error {
	if err := c.checkAdmin(admin); err != nil {
		return err
	}
	i := slices.IndexFunc(c.st.Nodes, func(n *nodeRecord) bool { return n.ID == id })
	if i < 0 {
		return ErrNotFound
	}
	n := c.st.Nodes[i]
	delete(c.byToken, n.TokenHash)
	c.st.Nodes = slices.Delete(c.st.Nodes, i, i+1)
	c.st.Revoked = append(c.st.Revoked, n.NodeKey)
	c.st.Version++
	return nil
}

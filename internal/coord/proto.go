// Package coord is the coordination of the mesh (contract §3.1): node
// registration, the map of peers that the policy allows, endpoint reports,
// revocation, the node's cache of the map and the reflexive endpoint
// service.
//
// The rules live in Core, which keeps no clock, opens no socket and starts
// no goroutine, so the simulator can drive it; Server carries Core over
// HTTPS with long-polls and persists its state, and Client is the node's
// side.
package coord

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
)

// Key is a 32-byte public key, standard base64 in JSON as in wg(8).
type Key [32]byte

// MarshalText encodes k in standard base64.
func (k Key) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(k[:])), nil
}

// UnmarshalText decodes a standard base64 key of 32 bytes.
func (k *Key) UnmarshalText(b []byte) error {
	raw, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		return err
	}
	if len(raw) != len(k) {
		return fmt.Errorf("key is %d bytes, want 32", len(raw))
	}
	copy(k[:], raw)
	return nil
}

func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// RegisterRequest is the body of POST /v1/register.
type RegisterRequest struct {
	AuthKey  string   `json:"auth_key"`
	NodeKey  Key      `json:"node_key"`
	DiscoKey Key      `json:"disco_key"`
	Name     string   `json:"name"`
	Tags     []string `json:"tags"`
}

// RegisterResponse answers a registration.
type RegisterResponse struct {
	NodeID uint64     `json:"node_id"`
	Token  string     `json:"token"`
	Addr   netip.Addr `json:"addr"`
}

// Node is one node as the map shows it.
type Node struct {
	NodeID    uint64     `json:"node_id"`
	Name      string     `json:"name"`
	NodeKey   Key        `json:"node_key"`
	DiscoKey  Key        `json:"disco_key"`
	Addr      netip.Addr `json:"addr"`
	Endpoints []string   `json:"endpoints"`
}

// Netmap is the answer of GET /v1/netmap: the node itself and the peers
// the policy allows it, in node_id order.
type Netmap struct {
	Version uint64 `json:"version"`
	Self    Node   `json:"self"`
	Peers   []Node `json:"peers"`
	Relay   string `json:"relay"`
}

// EndpointsRequest is the body of POST /v1/endpoints.
type EndpointsRequest struct {
	Endpoints []string `json:"endpoints"`
}

// RevokeRequest is the body of POST /v1/admin/revoke.
type RevokeRequest struct {
	NodeID uint64 `json:"node_id"`
}

// Errors of Core; Server maps them to HTTP statuses.
var (
	ErrBadRequest   = errors.New("bad request")   // 400
	ErrUnauthorized = errors.New("unauthorized")  // 401: unknown token or auth key
	ErrForbidden    = errors.New("forbidden")     // 403: revoked key
	ErrNotFound     = errors.New("not found")     // 404
	ErrConflict     = errors.New("conflict")      // 409: name taken by another key
	ErrFull         = errors.New("address space") // 503: no address left
)

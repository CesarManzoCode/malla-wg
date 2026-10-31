package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/device"
)

// config is node.json (contract §3.4). Without coord_url the node runs in
// static mode from address and peers; with it, in mesh mode, where name
// and tags identify the node to the policy. The relay fields are read but
// not used yet.
type config struct {
	PrivateKeyFile   string       `json:"private_key_file"`
	ListenPort       uint16       `json:"listen_port"`
	CoordURL         string       `json:"coord_url"`
	CoordFingerprint string       `json:"coord_fingerprint"`
	AuthKey          string       `json:"auth_key"`
	RelayURL         string       `json:"relay_url"`
	RelayFingerprint string       `json:"relay_fingerprint"`
	StateDir         string       `json:"state_dir"`
	TUNName          string       `json:"tun_name"`
	Address          string       `json:"address"`
	Peers            []peerConfig `json:"peers"`
	Name             string       `json:"name"`
	Tags             []string     `json:"tags"`
}

type peerConfig struct {
	PublicKey        string   `json:"public_key"`
	PresharedKeyFile string   `json:"preshared_key_file"`
	Endpoint         string   `json:"endpoint"`
	AllowedIPs       []string `json:"allowed_ips"`
	// PersistentKeepalive is in seconds, 0 to disable, as in wg(8).
	PersistentKeepalive int `json:"persistent_keepalive"`
}

// static is a validated static-mode configuration.
type static struct {
	listenPort uint16
	tunName    string
	address    netip.Prefix
	dev        device.Config
}

// meshMode is a validated mesh-mode configuration.
type meshMode struct {
	listenPort uint16
	tunName    string
	privateKey [32]byte
	name       string
	tags       []string
	coordURL   string
	coordFP    string
	authKey    string
	stateDir   string
}

func readConfig(path string) (*config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// relTo makes p relative to the directory of the configuration file.
func relTo(path, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(filepath.Dir(path), p)
}

func loadMesh(path string, c *config) (*meshMode, error) {
	if c.Address != "" || len(c.Peers) > 0 {
		return nil, errors.New("address and peers are for static mode; with coord_url the map brings them")
	}
	if c.StateDir == "" {
		return nil, errors.New("state_dir is required with coord_url")
	}
	if c.Name == "" {
		return nil, errors.New("name is required with coord_url")
	}
	m := &meshMode{
		listenPort: c.ListenPort, tunName: c.TUNName, name: c.Name, tags: c.Tags,
		coordURL: c.CoordURL, coordFP: c.CoordFingerprint, authKey: c.AuthKey,
		stateDir: relTo(path, c.StateDir),
	}
	var err error
	if m.privateKey, err = readKeyFile(relTo(path, c.PrivateKeyFile)); err != nil {
		return nil, fmt.Errorf("private_key_file: %w", err)
	}
	return m, nil
}

func loadStatic(path string, c *config) (*static, error) {
	if c.Name != "" || len(c.Tags) > 0 {
		return nil, errors.New("name and tags need coord_url")
	}
	rel := func(p string) string { return relTo(path, p) }
	var err error
	s := &static{listenPort: c.ListenPort, tunName: c.TUNName}
	if s.address, err = netip.ParsePrefix(c.Address); err != nil {
		return nil, fmt.Errorf("address: %w", err)
	}
	if s.dev.PrivateKey, err = readKeyFile(rel(c.PrivateKeyFile)); err != nil {
		return nil, fmt.Errorf("private_key_file: %w", err)
	}
	for i, pc := range c.Peers {
		var p device.PeerConfig
		if p.PublicKey, err = parseKey(pc.PublicKey); err != nil {
			return nil, fmt.Errorf("peers[%d].public_key: %w", i, err)
		}
		if pc.PresharedKeyFile != "" {
			if p.PresharedKey, err = readKeyFile(rel(pc.PresharedKeyFile)); err != nil {
				return nil, fmt.Errorf("peers[%d].preshared_key_file: %w", i, err)
			}
		}
		if pc.Endpoint != "" {
			if p.Endpoint, err = netip.ParseAddrPort(pc.Endpoint); err != nil {
				return nil, fmt.Errorf("peers[%d].endpoint: %w", i, err)
			}
		}
		for _, a := range pc.AllowedIPs {
			pfx, err := netip.ParsePrefix(a)
			if err != nil {
				return nil, fmt.Errorf("peers[%d].allowed_ips: %w", i, err)
			}
			p.AllowedIPs = append(p.AllowedIPs, pfx.Masked())
		}
		if pc.PersistentKeepalive < 0 || pc.PersistentKeepalive > 65535 {
			return nil, fmt.Errorf("peers[%d].persistent_keepalive: out of range", i)
		}
		p.PersistentKeepalive = time.Duration(pc.PersistentKeepalive) * time.Second
		s.dev.Peers = append(s.dev.Peers, p)
	}
	return s, nil
}

// parseKey decodes a 32-byte key in standard base64, the format of wg(8).
func parseKey(s string) ([32]byte, error) {
	var k [32]byte
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return k, err
	}
	if len(b) != len(k) {
		return k, fmt.Errorf("key is %d bytes, want 32", len(b))
	}
	copy(k[:], b)
	return k, nil
}

func readKeyFile(path string) ([32]byte, error) {
	if path == "" {
		return [32]byte{}, errors.New("missing")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return [32]byte{}, err
	}
	return parseKey(string(b))
}

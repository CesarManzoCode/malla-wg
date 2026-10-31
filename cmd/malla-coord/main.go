// Command malla-coord is the coordination server of the mesh (contract
// §3.1): HTTPS with a self-signed certificate kept in state_dir, and the
// reflexive endpoint service over UDP.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/CesarManzoCode/malla-wg/internal/coord"
)

// config is coord.json (contract §3.4).
type config struct {
	Listen     string   `json:"listen"`
	STUNListen string   `json:"stun_listen"`
	StateDir   string   `json:"state_dir"`
	AdminToken string   `json:"admin_token"`
	AuthKeys   []string `json:"auth_keys"`
	PolicyFile string   `json:"policy_file"`
}

func main() {
	path := flag.String("config", "", "coordination configuration file")
	flag.Parse()
	if *path == "" {
		fmt.Fprintln(os.Stderr, "usage: malla-coord -config coord.json")
		os.Exit(2)
	}
	if err := run(*path); err != nil {
		fmt.Fprintln(os.Stderr, "malla-coord:", err)
		os.Exit(1)
	}
}

// readJSON decodes path into v, rejecting unknown fields.
func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func run(path string) error {
	var c config
	if err := readJSON(path, &c); err != nil {
		return err
	}
	if c.Listen == "" {
		return errors.New("listen is required")
	}
	if c.STUNListen == "" {
		c.STUNListen = fmt.Sprintf(":%d", coord.DefaultReflexivePort)
	}
	// Relative paths are relative to the configuration file.
	rel := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(filepath.Dir(path), p)
	}
	var policy *coord.Policy
	if c.PolicyFile != "" {
		policy = new(coord.Policy)
		if err := readJSON(rel(c.PolicyFile), policy); err != nil {
			return fmt.Errorf("policy_file: %w", err)
		}
	}
	srv, err := coord.NewServer(coord.ServerConfig{
		StateDir:   rel(c.StateDir),
		AdminToken: c.AdminToken,
		AuthKeys:   c.AuthKeys,
		Policy:     policy,
	})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	ua, err := net.ResolveUDPAddr("udp", c.STUNListen)
	if err != nil {
		ln.Close()
		return fmt.Errorf("stun_listen: %w", err)
	}
	uc, err := net.ListenUDP("udp", ua)
	if err != nil {
		ln.Close()
		return err
	}
	defer uc.Close()
	go coord.ServeReflexive(uc)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Tests and operators read the fingerprint to pin from this line.
	fmt.Printf("malla-coord: listen %s stun %s fingerprint %s\n", ln.Addr(), uc.LocalAddr(), srv.Fingerprint())
	return srv.Serve(ctx, ln)
}

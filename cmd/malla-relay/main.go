// Command malla-relay is the HTTPS relay of the mesh (contract §3.2): it
// forwards WireGuard and disco datagrams between nodes that cannot reach
// each other by UDP, with a self-signed certificate kept in state_dir.
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

	"github.com/CesarManzoCode/malla-wg/internal/relay"
)

// config is relay.json.
type config struct {
	Listen      string `json:"listen"`
	StateDir    string `json:"state_dir"`
	CaptureFile string `json:"capture_file"`
}

func main() {
	path := flag.String("config", "", "relay configuration file")
	flag.Parse()
	if *path == "" {
		fmt.Fprintln(os.Stderr, "usage: malla-relay -config relay.json")
		os.Exit(2)
	}
	if err := run(*path); err != nil {
		fmt.Fprintln(os.Stderr, "malla-relay:", err)
		os.Exit(1)
	}
}

func run(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var c config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if c.Listen == "" {
		return errors.New("listen is required")
	}
	if c.StateDir == "" {
		return errors.New("state_dir is required")
	}
	// Relative paths are relative to the configuration file.
	rel := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(filepath.Dir(path), p)
	}
	srv, err := relay.NewServer(relay.ServerConfig{
		StateDir:    rel(c.StateDir),
		CaptureFile: rel(c.CaptureFile),
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		},
	})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Tests and operators read the fingerprint to pin from this line.
	fmt.Printf("malla-relay: listen %s fingerprint %s\n", ln.Addr(), srv.Fingerprint())
	return srv.Serve(ctx, ln)
}

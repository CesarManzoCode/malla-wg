package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/mesh"
)

// socketEnv names the control socket when neither -socket nor -config is
// given.
const socketEnv = "MALLA_SOCKET"

// waitPoll spaces the status queries of wait-direct.
const waitPoll = 50 * time.Millisecond

// socketFlags adds the flags that locate the control socket: -socket, or
// the state_dir of -config, or $MALLA_SOCKET.
func socketFlags(fs *flag.FlagSet) func() (string, error) {
	sock := fs.String("socket", "", "control socket (default: state_dir/control.sock of -config, or $"+socketEnv+")")
	cfg := fs.String("config", "", "node configuration file, whose state_dir holds the control socket")
	return func() (string, error) {
		switch {
		case *sock != "":
			return *sock, nil
		case *cfg != "":
			c, err := readConfig(*cfg)
			if err != nil {
				return "", err
			}
			if c.StateDir == "" {
				return "", fmt.Errorf("%s has no state_dir, so the node has no control socket", *cfg)
			}
			return filepath.Join(relTo(*cfg, c.StateDir), mesh.ControlSocket), nil
		case os.Getenv(socketEnv) != "":
			return os.Getenv(socketEnv), nil
		}
		return "", errors.New("say where the control socket is: -socket, -config or $" + socketEnv)
	}
}

// status prints one line per peer, `<name> <addr> direct|relay <endpoint>`
// (contract §3.4), or the JSON of the control socket with -json. A path
// that is neither shows as "none", and the endpoint of a path that is not
// direct as "-".
func status(args []string) int {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	socket := socketFlags(fs)
	fs.Parse(args)
	path, err := socket()
	if err != nil {
		fmt.Fprintln(os.Stderr, "malla:", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	peers, err := mesh.QueryStatus(ctx, path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "malla: status:", err)
		return 1
	}
	if *asJSON {
		b, _ := json.Marshal(map[string]any{"peers": peers})
		fmt.Println(string(b))
		return 0
	}
	for _, p := range peers {
		fmt.Printf("%s %s %s %s\n", p.Name, p.Addr, p.Path, p.Endpoint)
	}
	return 0
}

// waitDirect exits with 0 as soon as the peer named -peer has a direct
// path, and with 1 if it has none when -timeout runs out. A node that
// does not answer yet, or does not know the peer yet, counts as no direct
// path.
func waitDirect(args []string) int {
	fs := flag.NewFlagSet("wait-direct", flag.ExitOnError)
	peer := fs.String("peer", "", "name of the peer")
	timeout := fs.Duration("timeout", 30*time.Second, "how long to wait")
	socket := socketFlags(fs)
	fs.Parse(args)
	if *peer == "" || *timeout < 0 {
		fmt.Fprintln(os.Stderr, "usage: malla wait-direct -peer <name> -timeout <dur>")
		return 2
	}
	path, err := socket()
	if err != nil {
		fmt.Fprintln(os.Stderr, "malla:", err)
		return 2
	}
	start := time.Now()
	deadline := start.Add(*timeout)
	last := "no answer from the node"
	for {
		// The last query may finish a little after the deadline rather
		// than not run at all.
		qdl := deadline
		if t := time.Now().Add(time.Second); qdl.Before(t) {
			qdl = t
		}
		ctx, cancel := context.WithDeadline(context.Background(), qdl)
		peers, err := mesh.QueryStatus(ctx, path)
		cancel()
		switch {
		case err != nil:
			last = err.Error()
		default:
			last = "peer not in the map"
			for _, p := range peers {
				if p.Name != *peer {
					continue
				}
				if p.Path == "direct" {
					fmt.Printf("%s direct %s after %v\n", p.Name, p.Endpoint, time.Since(start).Round(time.Millisecond))
					return 0
				}
				last = "path " + p.Path
			}
		}
		left := time.Until(deadline)
		if left <= 0 {
			fmt.Fprintf(os.Stderr, "malla: %s has no direct path after %v (%s)\n", *peer, *timeout, last)
			return 1
		}
		time.Sleep(min(waitPoll, left))
	}
}

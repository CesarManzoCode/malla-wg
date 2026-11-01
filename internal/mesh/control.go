package mesh

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/coord"
	"github.com/CesarManzoCode/malla-wg/internal/device"
	"github.com/CesarManzoCode/malla-wg/internal/magic"
)

// ControlSocket is the name of the control socket inside state_dir
// (contract §3.4).
const ControlSocket = "control.sock"

// controlTimeout bounds one exchange on the control socket.
const controlTimeout = 5 * time.Second

// PeerStatus is one peer as `malla status` shows it.
type PeerStatus struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
	Key  string `json:"key"`
	// Path is "direct" with a confirmed direct address, "relay" with the
	// relay up, else "none".
	Path string `json:"path"`
	// Endpoint is the direct address, "-" when the path is not direct.
	Endpoint string `json:"endpoint"`
	// RTTMillis is the round trip of the direct address, 0 if unmeasured.
	RTTMillis float64 `json:"rtt_ms"`
}

// controlRequest is one line a client writes on the control socket.
type controlRequest struct {
	Cmd string `json:"cmd"`
}

// controlResponse is the one line the node answers.
type controlResponse struct {
	Peers []PeerStatus `json:"peers"`
	Error string       `json:"error,omitempty"`
}

// peerInfo is what the map says about a peer, for the status.
type peerInfo struct {
	name string
	addr string
}

// setPeerInfo remembers the names and addresses of the map's peers.
func (n *Node) setPeerInfo(peers []coord.Node) {
	m := make(map[[32]byte]peerInfo, len(peers))
	for _, p := range peers {
		info := peerInfo{name: p.Name, addr: "-"}
		if p.Addr.IsValid() {
			info.addr = p.Addr.String()
		}
		m[p.NodeKey] = info
	}
	n.mu.Lock()
	n.info = m
	n.mu.Unlock()
}

// Status reports every peer of the bind, sorted by name and then key.
func (n *Node) Status(ctx context.Context) ([]PeerStatus, error) {
	var st []magic.PeerStatus
	if err := n.rt.Query(ctx, func(*device.Device) { st = n.bind.Status(n.rt.Now()) }); err != nil {
		return nil, err
	}
	n.mu.Lock()
	info := n.info
	n.mu.Unlock()
	out := make([]PeerStatus, 0, len(st))
	for _, s := range st {
		i, ok := info[s.Key]
		if !ok {
			i = peerInfo{name: "-", addr: "-"}
		}
		ps := PeerStatus{Name: i.name, Addr: i.addr, Key: coord.Key(s.Key).String(), Path: s.Path.String(), Endpoint: "-"}
		if s.Path == magic.PathDirect {
			ps.Endpoint = s.Endpoint.String()
			ps.RTTMillis = float64(s.RTT) / 1e6
		}
		out = append(out, ps)
	}
	slices.SortFunc(out, func(a, b PeerStatus) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Key, b.Key))
	})
	return out, nil
}

// listenControl opens state_dir/control.sock, replacing a stale socket
// of an earlier run, readable and writable by the owner only.
func listenControl(stateDir string) (net.Listener, error) {
	path := filepath.Join(stateDir, ControlSocket)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// serveControl answers the control socket until ctx is done, then closes
// it and removes the socket file.
func (n *Node) serveControl(ctx context.Context) {
	ln := n.ctl
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	defer os.Remove(filepath.Join(n.cfg.StateDir, ControlSocket))
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				n.cfg.Logf("mesh: control: %v", err)
			}
			return
		}
		go n.controlConn(ctx, c)
	}
}

// controlConn handles one request: one JSON line in, one JSON line out.
func (n *Node) controlConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(controlTimeout))
	var resp controlResponse
	line, err := bufio.NewReader(c).ReadBytes('\n')
	var req controlRequest
	switch {
	case err != nil:
		return
	case json.Unmarshal(line, &req) != nil:
		resp.Error = "malformed request"
	case req.Cmd == "status":
		qctx, cancel := context.WithTimeout(ctx, controlTimeout)
		resp.Peers, err = n.Status(qctx)
		cancel()
		if err != nil {
			resp.Error = err.Error()
		}
	default:
		resp.Error = fmt.Sprintf("unknown command %q", req.Cmd)
	}
	b, _ := json.Marshal(resp)
	c.Write(append(b, '\n'))
}

// QueryStatus asks the node behind the control socket at path for the
// status of its peers.
func QueryStatus(ctx context.Context, path string) ([]PeerStatus, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	deadline := time.Now().Add(controlTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	c.SetDeadline(deadline)
	req, _ := json.Marshal(controlRequest{Cmd: "status"})
	if _, err := c.Write(append(req, '\n')); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var resp controlResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, errors.New(resp.Error)
	}
	return resp.Peers, nil
}

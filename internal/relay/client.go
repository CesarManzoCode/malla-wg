package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/coord"
)

// Reconnection backoff of the client.
const (
	minBackoff = time.Second
	maxBackoff = 10 * time.Second
)

// ClientConfig configures a Client. The callbacks are called from the
// client's reader goroutine and must not block.
type ClientConfig struct {
	// URL is https://host[:port]; the client opens Path on it.
	URL string
	// Fingerprint pins the relay's certificate, as coord_fingerprint
	// pins the coordination's.
	Fingerprint string
	NodeKey     [KeyLen]byte
	// OnPacket receives each datagram relayed to the node; datagram is
	// only valid during the call.
	OnPacket func(src [KeyLen]byte, datagram []byte)
	// OnState, if set, is told when the connection comes up and goes
	// down.
	OnState func(up bool)
	// OnPeerGone, if set, is told that a destination is not connected.
	OnPeerGone func(key [KeyLen]byte)
	Logf       func(format string, args ...any)
}

// Client is a node's connection to the relay; Run keeps it up.
type Client struct {
	cfg  ClientConfig
	addr string
	host string
	tls  *tls.Config
	cur  atomic.Pointer[frameConn]
}

// NewClient checks cfg and returns a client; Run connects it.
func NewClient(cfg ClientConfig) (*Client, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("relay: url %q must be https://host[:port]", cfg.URL)
	}
	tc, err := coord.PinnedTLSConfig(cfg.Fingerprint)
	if err != nil {
		return nil, err
	}
	tc.NextProtos = []string{"http/1.1"}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.OnPacket == nil {
		cfg.OnPacket = func([KeyLen]byte, []byte) {}
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	return &Client{cfg: cfg, addr: addr, host: u.Host, tls: tc}, nil
}

// URL returns the relay's URL.
func (c *Client) URL() string { return c.cfg.URL }

// Connected reports whether the client has a connection up.
func (c *Client) Connected() bool { return c.cur.Load() != nil }

// Send queues datagram for the node with key dst and reports whether it
// was queued: it fails without a connection or with the queue full, and
// never blocks.
func (c *Client) Send(dst [KeyLen]byte, datagram []byte) bool {
	fc := c.cur.Load()
	if fc == nil || len(datagram) > MaxDatagram {
		return false
	}
	return fc.enqueue(AppendFrame(make([]byte, 0, HeaderLen+KeyLen+len(datagram)), TypeSendPacket, dst[:], datagram))
}

// Run connects, and reconnects with backoff, until ctx is done.
func (c *Client) Run(ctx context.Context) error {
	backoff := minBackoff
	for ctx.Err() == nil {
		start := time.Now()
		err := c.session(ctx)
		if ctx.Err() != nil {
			break
		}
		c.cfg.Logf("relay: %s: %v", c.cfg.URL, err)
		if time.Since(start) > maxBackoff {
			backoff = minBackoff
		}
		t := time.NewTimer(backoff)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
		}
		backoff = min(2*backoff, maxBackoff)
	}
	return nil
}

// session opens one connection, upgrades it, says hello and reads frames
// until it fails.
func (c *Client) session(ctx context.Context) error {
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: handshakeTimeout}, Config: c.tls}
	nc, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { nc.Close() })
	defer stop()
	defer nc.Close()

	nc.SetDeadline(time.Now().Add(handshakeTimeout))
	req, err := http.NewRequest(http.MethodGet, "https://"+c.host+Path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", Protocol)
	if err := req.Write(nc); err != nil {
		return err
	}
	br := bufio.NewReader(nc)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(resp.Header.Get("Upgrade"), Protocol) {
		resp.Body.Close()
		return fmt.Errorf("upgrade refused: %s", resp.Status)
	}
	if _, err := nc.Write(AppendFrame(nil, TypeClientHello, c.cfg.NodeKey[:])); err != nil {
		return err
	}
	t, _, buf, err := ReadFrame(br, nil)
	if err != nil {
		return err
	}
	if t != TypeServerHello {
		return fmt.Errorf("got %s, want ServerHello", t)
	}
	nc.SetDeadline(time.Time{})

	fc := newFrameConn(nc)
	defer fc.close()
	c.cur.Store(fc)
	if c.cfg.OnState != nil {
		c.cfg.OnState(true)
	}
	defer func() {
		c.cur.CompareAndSwap(fc, nil)
		if c.cfg.OnState != nil {
			c.cfg.OnState(false)
		}
	}()
	for {
		nc.SetReadDeadline(time.Now().Add(ReadTimeout))
		var payload []byte
		t, payload, buf, err = ReadFrame(br, buf)
		if err != nil {
			return err
		}
		switch t {
		case TypeRecvPacket:
			src, dg, err := SplitPacket(payload)
			if err != nil {
				return err
			}
			c.cfg.OnPacket(src, dg)
		case TypePeerGone:
			key, err := ParseKey(payload)
			if err != nil {
				return err
			}
			if c.cfg.OnPeerGone != nil {
				c.cfg.OnPeerGone(key)
			}
		case TypeKeepAlive:
		default:
			return fmt.Errorf("unexpected %s frame", t)
		}
	}
}

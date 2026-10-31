// Package device is the sans-IO core of a WireGuard device: peers, the
// current, previous and next keypairs, the timers of the Linux kernel's
// timers.c, rekey, keepalives, roaming, cookies under load and the
// allowed-IPs table.
//
// It never reads a clock, opens a socket or starts a goroutine. The caller
// passes the monotonic time now (nanoseconds) and the input bytes to
// HandleUDP, HandleTUN or Tick, sends the returned datagrams, writes the
// returned packets to the TUN and calls Tick again at NextDeadline.
package device

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/noise"
)

// Thresholds of the contract §6, in nanoseconds, from the kernel's
// messages.h.
const (
	RekeyAfterTime      int64 = 120e9
	RejectAfterTime     int64 = 180e9
	RekeyTimeout        int64 = 5e9
	RekeyTimeoutJitter  int64 = 333e6 // exclusive bound: HZ/3
	KeepaliveTimeout    int64 = 10e9
	RekeyAttemptTime    int64 = 90e9
	ZeroKeyMaterialTime int64 = 3 * RejectAfterTime
	// RekeyOnReceiveTime is REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT -
	// REKEY_TIMEOUT (165 s), the kernel's receive.c.
	RekeyOnReceiveTime int64 = RejectAfterTime - KeepaliveTimeout - RekeyTimeout

	RekeyAfterMessages  uint64 = 1 << 60
	RejectAfterMessages uint64 = noise.RejectAfterMessages

	// UnderLoadHandshakes handshake messages received within
	// UnderLoadWindow put the device under load for UnderLoadWindow more.
	UnderLoadHandshakes       = 512
	UnderLoadWindow     int64 = 1e9

	// MaxStagedPackets is the kernel's MAX_STAGED_PACKETS: packets queued
	// per peer while there is no usable keypair.
	MaxStagedPackets = 128
)

// Never is what NextDeadline returns when no timer is armed.
const Never int64 = math.MaxInt64

// Reasons of drop events.
const (
	ReasonType             = "type"        // not a WireGuard message
	ReasonMAC1             = "mac1"        // invalid mac1
	ReasonCookie           = "cookie"      // no valid mac2 under load; a cookie reply was sent
	ReasonCookieReply      = "cookiereply" // cookie reply did not open
	ReasonHandshake        = "handshake"   // initiation or response rejected
	ReasonIndex            = "index"       // unknown receiver index
	ReasonExpired          = "expired"     // keypair older than REJECT_AFTER_TIME
	ReasonDecrypt          = "decrypt"     // AEAD failed
	ReasonReplay           = "replay"      // counter replayed, too old or over the limit
	ReasonInvalid          = "invalid"     // not an IPv4 or IPv6 packet
	ReasonAllowedIPs       = "allowedips"  // inner source outside the peer's allowed IPs
	ReasonNoRoute          = "noroute"     // no peer for the destination
	ReasonNoEndpoint       = "noendpoint"  // peer has no endpoint
	ReasonHandshakeTimeout = "handshaketimeout"
	ReasonRandom           = "random" // the randomness source failed
)

// Reasons of rekey events, one per initiation sent.
const (
	RekeyNoKeypair    = "nokeypair"    // packets to send and no usable keypair
	RekeyRetry        = "retry"        // REKEY_TIMEOUT without a response
	RekeySendAge      = "sendage"      // initiator sent with a key of REKEY_AFTER_TIME
	RekeySendMessages = "sendmessages" // REKEY_AFTER_MESSAGES sent
	RekeyReceiveAge   = "receiveage"   // initiator received with a key of 165 s
	RekeyNoReply      = "noreply"      // data sent and nothing received
)

// EventKind classifies events.
type EventKind uint8

const (
	EventHandshake EventKind = iota + 1 // a session was derived; Reason is "initiator" or "responder"
	EventEndpoint                       // the peer's endpoint changed to Endpoint
	EventRekey                          // an initiation was sent; Reason says why
	EventDrop                           // something was dropped; Reason says why
)

func (k EventKind) String() string {
	switch k {
	case EventHandshake:
		return "handshake"
	case EventEndpoint:
		return "endpoint"
	case EventRekey:
		return "rekey"
	case EventDrop:
		return "drop"
	}
	return fmt.Sprintf("EventKind(%d)", uint8(k))
}

// Event reports something that happened. Peer is zero when the message
// could not be attributed to a peer.
type Event struct {
	Kind     EventKind
	Peer     [noise.KeySize]byte
	Reason   string
	Endpoint netip.AddrPort
}

// Datagram is a UDP payload to send to Dst.
type Datagram struct {
	Dst  netip.AddrPort
	Data []byte
}

// Output is what one call produces, in the order it happened.
type Output struct {
	Datagrams []Datagram
	Packets   [][]byte // for the TUN
	Events    []Event
}

// PeerConfig describes one peer.
type PeerConfig struct {
	PublicKey    [noise.KeySize]byte
	PresharedKey [noise.KeySize]byte // all zeros when there is none
	AllowedIPs   []netip.Prefix
	Endpoint     netip.AddrPort // the zero value when unknown
	// PersistentKeepalive is the interval of persistent keepalives, 0 to
	// disable them.
	PersistentKeepalive time.Duration
}

// Config describes a device.
type Config struct {
	PrivateKey [noise.KeySize]byte
	Peers      []PeerConfig
	Rand       io.Reader
	// WallOffset is the Unix time in nanoseconds at now = 0: TAI64N
	// timestamps use now + WallOffset, so the core never reads a clock.
	WallOffset int64
	// MTU bounds the transport padding; 0 pads to a multiple of 16.
	MTU int
	// ForceUnderLoad makes the device behave as under load, for tests.
	ForceUnderLoad bool
}

// Device is the state of one WireGuard interface.
type Device struct {
	local      *noise.Local
	rnd        io.Reader
	wallOffset int64
	mtu        int
	forceLoad  bool

	peers   []*peer // configuration order: timers fire in this order
	byKey   map[[noise.KeySize]byte]*peer
	indices map[uint32]indexEntry
	routes  allowedIPs

	// Arrival times of the last UnderLoadHandshakes handshake messages.
	hsTimes   [UnderLoadHandshakes]int64
	hsCount   int
	hsNext    int
	loadUntil int64

	out Output
}

// indexEntry is what a local index points to: a pending handshake when kp
// is nil, a keypair otherwise.
type indexEntry struct {
	peer *peer
	kp   *keypair
}

// New returns a device for cfg.
func New(cfg Config) (*Device, error) {
	if cfg.Rand == nil {
		return nil, errors.New("device: Config.Rand is nil")
	}
	d := &Device{
		local:      noise.NewLocal(cfg.PrivateKey),
		rnd:        cfg.Rand,
		wallOffset: cfg.WallOffset,
		mtu:        cfg.MTU,
		forceLoad:  cfg.ForceUnderLoad,
		byKey:      make(map[[noise.KeySize]byte]*peer),
		indices:    make(map[uint32]indexEntry),
	}
	for i, pc := range cfg.Peers {
		if _, dup := d.byKey[pc.PublicKey]; dup {
			return nil, fmt.Errorf("device: peer %d: duplicate public key", i)
		}
		np, err := d.local.NewPeer(pc.PublicKey, pc.PresharedKey)
		if err != nil {
			return nil, fmt.Errorf("device: peer %d: %w", i, err)
		}
		if pc.PersistentKeepalive < 0 {
			return nil, fmt.Errorf("device: peer %d: negative persistent keepalive", i)
		}
		p := &peer{
			key:        pc.PublicKey,
			noise:      np,
			endpoint:   pc.Endpoint,
			persistent: int64(pc.PersistentKeepalive),
		}
		for _, pfx := range pc.AllowedIPs {
			if !pfx.IsValid() {
				return nil, fmt.Errorf("device: peer %d: invalid allowed IP prefix", i)
			}
			d.routes.insert(pfx, p)
		}
		d.peers = append(d.peers, p)
		d.byKey[p.key] = p
	}
	return d, nil
}

// PublicKey returns the device's static public key.
func (d *Device) PublicKey() [noise.KeySize]byte { return d.local.PublicKey() }

// Endpoint returns the current endpoint of the peer with public key pub.
func (d *Device) Endpoint(pub [noise.KeySize]byte) (netip.AddrPort, bool) {
	p := d.byKey[pub]
	if p == nil || !p.endpoint.IsValid() {
		return netip.AddrPort{}, false
	}
	return p.endpoint, true
}

// HandleUDP processes a datagram b received from src.
func (d *Device) HandleUDP(now int64, src netip.AddrPort, b []byte) Output {
	switch noise.MessageType(b) {
	case noise.TypeInitiation:
		d.noteHandshake(now)
		d.handleInitiation(now, src, b)
	case noise.TypeResponse:
		d.noteHandshake(now)
		d.handleResponse(now, src, b)
	case noise.TypeCookieReply:
		d.noteHandshake(now)
		d.handleCookieReply(now, b)
	case noise.TypeTransport:
		d.handleTransport(now, src, b)
	default:
		d.drop(nil, ReasonType)
	}
	return d.take()
}

// HandleTUN routes an IP packet read from the TUN to the peer whose
// allowed IPs hold its destination, and sends it or stages it until a
// keypair exists.
func (d *Device) HandleTUN(now int64, pkt []byte) Output {
	pkt, _, dst, ok := parseIP(pkt)
	switch p := d.routes.lookup(dst); {
	case !ok:
		d.drop(nil, ReasonInvalid)
	case p == nil:
		d.drop(nil, ReasonNoRoute)
	case !p.endpoint.IsValid():
		d.drop(p, ReasonNoEndpoint)
	default:
		if len(p.staged) >= MaxStagedPackets {
			p.staged = p.staged[1:]
		}
		p.staged = append(p.staged, bytes.Clone(pkt))
		d.sendStaged(now, p)
	}
	return d.take()
}

// Tick fires every timer due at now.
func (d *Device) Tick(now int64) Output {
	for _, p := range d.peers {
		d.fireTimers(now, p)
	}
	return d.take()
}

// NextDeadline returns the earliest armed timer, or Never.
func (d *Device) NextDeadline() int64 {
	next := Never
	for _, p := range d.peers {
		next = min(next, p.nextDeadline())
	}
	return next
}

func (d *Device) take() Output {
	out := d.out
	d.out = Output{}
	return out
}

func (d *Device) send(dst netip.AddrPort, b []byte) {
	d.out.Datagrams = append(d.out.Datagrams, Datagram{Dst: dst, Data: b})
}

func (d *Device) event(kind EventKind, p *peer, reason string) {
	e := Event{Kind: kind, Reason: reason}
	if p != nil {
		e.Peer = p.key
	}
	d.out.Events = append(d.out.Events, e)
}

func (d *Device) drop(p *peer, reason string) { d.event(EventDrop, p, reason) }

// random fills b from the randomness source, or reports a drop.
func (d *Device) random(b []byte) bool {
	if _, err := io.ReadFull(d.rnd, b); err != nil {
		d.drop(nil, ReasonRandom)
		return false
	}
	return true
}

// jitter returns a uniform delay in [0, RekeyTimeoutJitter).
func (d *Device) jitter() int64 {
	var b [8]byte
	if !d.random(b[:]) {
		return 0
	}
	return int64(binary.LittleEndian.Uint64(b[:]) % uint64(RekeyTimeoutJitter))
}

// newIndex draws a random local index that is not in use.
func (d *Device) newIndex() (uint32, bool) {
	for range 16 {
		var b [4]byte
		if !d.random(b[:]) {
			return 0, false
		}
		i := binary.LittleEndian.Uint32(b[:])
		if _, used := d.indices[i]; !used {
			return i, true
		}
	}
	return 0, false
}

// noteHandshake records the arrival of a handshake message: 512 within one
// second put the device under load for one more second.
func (d *Device) noteHandshake(now int64) {
	d.hsTimes[d.hsNext] = now
	d.hsNext = (d.hsNext + 1) % UnderLoadHandshakes
	if d.hsCount < UnderLoadHandshakes {
		d.hsCount++
	}
	// After the increment hsNext points at the oldest of the last 512.
	if d.hsCount == UnderLoadHandshakes && now-d.hsTimes[d.hsNext] < UnderLoadWindow {
		d.loadUntil = now + UnderLoadWindow
	}
}

func (d *Device) underLoad(now int64) bool {
	return d.forceLoad || now < d.loadUntil
}

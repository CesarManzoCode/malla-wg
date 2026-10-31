// Package interop holds the interoperability tests of the contract §7
// (criteria 5 to 10): the own node (internal/runtime) against the Linux
// kernel's WireGuard, configured with wgctrl inside a namespace built by
// verify/netns, and against wireguard-go running in this process on
// tun/netstack over 127.0.0.1, without privileges.
package interop

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/device"
	"github.com/CesarManzoCode/malla-wg/internal/noise"
	"github.com/CesarManzoCode/malla-wg/internal/runtime"
	"github.com/CesarManzoCode/malla-wg/internal/tun"
	"golang.org/x/net/ipv4"
)

// pingTimeout is how long one echo request waits for its reply, like
// `ping -W 2`.
const pingTimeout = 2 * time.Second

// pingData is the payload of every echo request the helpers send.
var pingData = []byte("malla-wg interop")

// Events records the own node's device events in order.
type Events struct {
	mu   sync.Mutex
	list []device.Event
}

func (e *Events) add(ev device.Event) {
	e.mu.Lock()
	e.list = append(e.list, ev)
	e.mu.Unlock()
}

// Last describes the last event, or says there was none.
func (e *Events) Last() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.list) == 0 {
		return "none"
	}
	ev := e.list[len(e.list)-1]
	return ev.Kind.String() + " " + ev.Reason
}

// Count returns how many events of kind with reason were recorded; an
// empty reason matches any.
func (e *Events) Count(kind device.EventKind, reason string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, ev := range e.list {
		if ev.Kind == kind && (reason == "" || ev.Reason == reason) {
			n++
		}
	}
	return n
}

// Index returns the position of the first event of kind with reason (empty
// matches any) at or after from, or -1.
func (e *Events) Index(kind device.EventKind, reason string, from int) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := max(from, 0); i < len(e.list); i++ {
		if ev := e.list[i]; ev.Kind == kind && (reason == "" || ev.Reason == reason) {
			return i
		}
	}
	return -1
}

// Wait polls until an event of kind with reason (empty matches any) is
// recorded or timeout passes, and reports whether one was.
func (e *Events) Wait(kind device.EventKind, reason string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for e.Count(kind, reason) == 0 {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true
}

// Handshake returns the reason ("initiator" or "responder") of the first
// handshake event, and whether there was one.
func (e *Events) Handshake() (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ev := range e.list {
		if ev.Kind == device.EventHandshake {
			return ev.Reason, true
		}
	}
	return "", false
}

// Own is a running own node.
type Own struct {
	Node   *runtime.Node
	Events *Events
	Addr   netip.Addr // tunnel address
	mem    *tun.Mem   // nil on a Linux TUN
	echoes chan []byte
}

// OwnPeer is the device configuration of the own node's only peer; an
// invalid endpoint leaves it unknown.
func OwnPeer(pub, psk [32]byte, allowed netip.Prefix, endpoint netip.AddrPort) device.PeerConfig {
	return device.PeerConfig{PublicKey: pub, PresharedKey: psk, AllowedIPs: []netip.Prefix{allowed}, Endpoint: endpoint}
}

// UnderLoad makes the own node behave as under load (ForceUnderLoad).
func UnderLoad(c *device.Config) { c.ForceUnderLoad = true }

// startOwn runs a node on conn and dev until t ends; mods adjust its
// device configuration.
func startOwn(t testing.TB, priv [32]byte, addr netip.Addr, peer device.PeerConfig, conn *net.UDPConn, dev tun.Device, mods ...func(*device.Config)) *Own {
	t.Helper()
	o := &Own{Events: &Events{}, Addr: addr}
	cfg := device.Config{PrivateKey: priv, Peers: []device.PeerConfig{peer}}
	for _, mod := range mods {
		mod(&cfg)
	}
	node, err := runtime.New(runtime.Config{
		Device:  cfg,
		Conn:    conn,
		TUN:     dev,
		OnEvent: o.Events.add,
	})
	if err != nil {
		conn.Close()
		dev.Close()
		t.Fatalf("own node: %v", err)
	}
	o.Node = node
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- node.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("own node stopped: %v", err)
		}
	})
	return o
}

// NewOwnMem runs an own node on 127.0.0.1 (a free port) with an in-memory
// TUN. A responder answers the ICMP echo requests sent to addr and hands
// the replies to Ping.
func NewOwnMem(t testing.TB, priv [32]byte, addr netip.Addr, peer device.PeerConfig, mods ...func(*device.Config)) *Own {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	mem := tun.NewMem("mem0", 256)
	o := startOwn(t, priv, addr, peer, conn, mem, mods...)
	o.mem, o.echoes = mem, make(chan []byte, 16)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go o.answer(stop)
	return o
}

// answer replies to echo requests for o.Addr and queues echo replies.
func (o *Own) answer(stop <-chan struct{}) {
	for {
		var pkt []byte
		select {
		case pkt = <-o.mem.Outbound():
		case <-stop:
			return
		}
		src, dst, msg, ok := parseICMPv4(pkt)
		if !ok || dst != o.Addr || len(msg) < 8 {
			continue
		}
		switch msg[0] {
		case 8: // echo request
			reply := icmpEcho(0, binary.BigEndian.Uint16(msg[4:]), binary.BigEndian.Uint16(msg[6:]), msg[8:])
			if o.mem.Inject(ipv4Packet(o.Addr, src, reply)) != nil {
				return
			}
		case 0: // echo reply
			select {
			case o.echoes <- msg:
			default:
			}
		}
	}
}

// Send injects one echo request with sequence 0 to dst into the in-memory
// TUN without waiting for its reply.
func (o *Own) Send(dst netip.Addr) error {
	if o.mem == nil {
		return errors.New("interop: Send needs an in-memory TUN")
	}
	return o.mem.Inject(ipv4Packet(o.Addr, dst, icmpEcho(8, 0x6d61, 0, pingData)))
}

// Ping sends up to tries echo requests from the in-memory TUN to dst and
// returns nil at the first reply.
func (o *Own) Ping(dst netip.Addr, tries int) error {
	if o.mem == nil {
		return errors.New("interop: Ping needs an in-memory TUN")
	}
	for seq := 1; seq <= tries; seq++ {
		if err := o.mem.Inject(ipv4Packet(o.Addr, dst, icmpEcho(8, 0x6d61, uint16(seq), pingData))); err != nil {
			return err
		}
		deadline := time.After(pingTimeout)
	wait:
		for {
			select {
			case msg := <-o.echoes:
				if isReply(msg, uint16(seq)) {
					return nil
				}
			case <-deadline:
				break wait
			}
		}
	}
	return fmt.Errorf("no echo reply from %s to %d requests", dst, tries)
}

// isReply reports whether msg is the echo reply to request seq.
func isReply(msg []byte, seq uint16) bool {
	return len(msg) >= 8 && msg[0] == 0 && binary.BigEndian.Uint16(msg[6:]) == seq && bytes.Equal(msg[8:], pingData)
}

// CookieRetry checks the own node's events as initiator against a peer
// under load: an accepted cookie reply, then a new initiation (which
// carries mac2, since the cookie is fresh), then the handshake.
func CookieRetry(o *Own) error {
	c := o.Events.Index(device.EventCookie, "", 0)
	if c < 0 {
		return errors.New("no cookie reply was accepted")
	}
	r := o.Events.Index(device.EventRekey, "", c)
	if r < 0 {
		return errors.New("no initiation after the cookie reply")
	}
	if o.Events.Index(device.EventHandshake, "initiator", r) < 0 {
		return errors.New("no handshake as initiator after the initiation with mac2")
	}
	return nil
}

// FloodSize is the number of initiations of a flood (contract §6, cookies
// under load), sent within one second.
const FloodSize = 4096

// FloodInitiation returns a serialized initiation to the static key target
// from a fresh key that target does not know. Its mac1, computed by
// internal/noise, is valid, so target spends a DH on it unless it is under
// load, in which case it answers with a cookie reply.
func FloodInitiation(t testing.TB, target [32]byte) []byte {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	p, err := noise.NewLocal(priv).NewPeer(target, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := p.CreateInitiation(rand.Reader, 0, time.Now().UnixNano(), 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// floodPause is how long the senders of a flood stop halfway through. It
// lets the receiver drain its handshake queue, which in wireguard-go holds
// 1024 entries, fewer than a flood, while it stays under load: the kernel
// and wireguard-go keep that state for 1 s after they last detect it.
const floodPause = 50 * time.Millisecond

// floodBatch is how many datagrams a flood sender passes to one sendmmsg
// call. One datagram per call is too slow for the kernel's handshake
// queue to reach the 512 entries that put it under load.
const floodBatch = 64

// floodAttempts is how many floods UnderLoadAttempts tries, floodGap
// apart, before failing because none put the oracle under load.
const (
	floodAttempts = 10
	floodGap      = time.Second
)

// Flood sends FloodSize copies of msg to dst, split evenly across conns
// that start together and send in parallel, and returns how long the
// sending took and whether the receiver was under load halfway through.
// Halfway through its share each sender waits for the others and, for
// floodPause, counts the cookie replies its socket gets: a receiver
// answers with a cookie only under load. If some arrived, the first
// sender calls trigger, which must return once what it starts has been
// sent; then all of them send the second half. What trigger sends thus
// reaches a receiver under load with room in its queue: wireguard-go
// drops what arrives at a full one, and a retry 5 s later would find it
// no longer under load. Send errors fail t.
func Flood(t testing.TB, conns []*net.UDPConn, dst netip.AddrPort, msg []byte, trigger func()) (took time.Duration, loaded bool) {
	t.Helper()
	share := FloodSize / len(conns)
	var wg, ready, half, counted sync.WaitGroup
	ready.Add(len(conns))
	half.Add(len(conns))
	counted.Add(len(conns))
	var cookies atomic.Int64
	begin, resume := make(chan struct{}), make(chan struct{})
	for i, c := range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pc, batch := ipv4.NewPacketConn(c), make([]ipv4.Message, floodBatch)
			for k := range batch {
				batch[k] = ipv4.Message{Buffers: [][]byte{msg}, Addr: net.UDPAddrFromAddrPort(dst)}
			}
			ready.Done()
			<-begin
			send := func(n int) bool {
				for n > 0 {
					m, err := pc.WriteBatch(batch[:min(n, len(batch))], 0)
					if err != nil {
						t.Errorf("flood sender %d: %v", i, err)
						return false
					}
					n -= m
				}
				return true
			}
			ok := send(share / 2)
			half.Done()
			half.Wait()
			cookies.Add(int64(countCookies(c, time.Now().Add(floodPause))))
			counted.Done()
			if i == 0 {
				counted.Wait()
				if loaded = cookies.Load() > 0; loaded {
					trigger()
				}
				close(resume)
			}
			<-resume
			if ok {
				send(share - share/2)
			}
		}()
	}
	ready.Wait()
	start := time.Now()
	close(begin)
	wg.Wait()
	return time.Since(start), loaded
}

// countCookies reads c until deadline and returns how many cookie replies
// it got.
func countCookies(c *net.UDPConn, deadline time.Time) int {
	defer c.SetReadDeadline(time.Time{})
	c.SetReadDeadline(deadline)
	buf := make([]byte, 1500)
	n := 0
	for {
		m, err := c.Read(buf)
		if err != nil {
			return n
		}
		if noise.MessageType(buf[:m]) == noise.TypeCookieReply {
			n++
		}
	}
}

// UnderLoadAttempts runs attempt, each time in a subtest of its own and
// floodGap after the previous one, until it reports that its flood put
// the oracle under load, at most floodAttempts times. An attempt whose
// flood did not says nothing about the own node, since a receiver that is
// not under load sends no cookie; an attempt that fails ends the loop.
func UnderLoadAttempts(t *testing.T, attempt func(t *testing.T, n int) (loaded bool)) {
	t.Helper()
	for n := 1; n <= floodAttempts; n++ {
		if n > 1 {
			time.Sleep(floodGap)
		}
		loaded := false
		if ok := t.Run(fmt.Sprintf("attempt-%d", n), func(t *testing.T) { loaded = attempt(t, n) }); !ok || loaded {
			return
		}
	}
	t.Fatalf("none of %d floods of %d initiations put the oracle under load", floodAttempts, FloodSize)
}

// Failure formats what a failed run reports (contract §7, k1-07): who
// initiated, the own node's last event and the state read from the
// oracle.
func Failure(initiator string, own *Own, oracle string) string {
	hs, ok := own.Events.Handshake()
	if !ok {
		hs = "none"
	}
	return fmt.Sprintf("initiator: %s; own handshake: %s; own last event: %s; oracle state:\n%s",
		initiator, hs, own.Events.Last(), strings.TrimSpace(oracle))
}

// icmpEcho builds an ICMP echo message of type typ (8 request, 0 reply).
func icmpEcho(typ byte, id, seq uint16, data []byte) []byte {
	b := make([]byte, 8+len(data))
	b[0] = typ
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], seq)
	copy(b[8:], data)
	binary.BigEndian.PutUint16(b[2:], checksum(b))
	return b
}

// ipv4Packet wraps an ICMP message in an IPv4 header with its checksum.
func ipv4Packet(src, dst netip.Addr, msg []byte) []byte {
	b := make([]byte, 20+len(msg))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8], b[9] = 64, 1 // TTL, ICMP
	s, d := src.As4(), dst.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[10:], checksum(b[:20]))
	copy(b[20:], msg)
	return b
}

// parseICMPv4 returns the addresses and the ICMP message of an IPv4 ICMP
// packet.
func parseICMPv4(pkt []byte) (src, dst netip.Addr, msg []byte, ok bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != 1 {
		return src, dst, nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:]))
	if ihl < 20 || total < ihl || total > len(pkt) {
		return src, dst, nil, false
	}
	src = netip.AddrFrom4([4]byte(pkt[12:16]))
	dst = netip.AddrFrom4([4]byte(pkt[16:20]))
	return src, dst, pkt[ihl:total], true
}

// checksum is the Internet checksum (RFC 1071).
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

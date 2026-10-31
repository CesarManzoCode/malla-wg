// Package interop holds the interoperability tests of the contract §7
// (criteria 5 to 8): the own node (internal/runtime) against the Linux
// kernel's WireGuard, configured with wgctrl inside a namespace built by
// verify/netns, and against wireguard-go running in this process on
// tun/netstack over 127.0.0.1, without privileges.
package interop

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/device"
	"github.com/CesarManzoCode/malla-wg/internal/runtime"
	"github.com/CesarManzoCode/malla-wg/internal/tun"
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

// startOwn runs a node on conn and dev until t ends.
func startOwn(t testing.TB, priv [32]byte, addr netip.Addr, peer device.PeerConfig, conn *net.UDPConn, dev tun.Device) *Own {
	t.Helper()
	o := &Own{Events: &Events{}, Addr: addr}
	node, err := runtime.New(runtime.Config{
		Device:  device.Config{PrivateKey: priv, Peers: []device.PeerConfig{peer}},
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
func NewOwnMem(t testing.TB, priv [32]byte, addr netip.Addr, peer device.PeerConfig) *Own {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	mem := tun.NewMem("mem0", 256)
	o := startOwn(t, priv, addr, peer, conn, mem)
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

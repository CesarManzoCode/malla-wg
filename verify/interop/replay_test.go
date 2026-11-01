//go:build linux

package interop

import (
	"bytes"
	"crypto/rand"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/device"
	"github.com/CesarManzoCode/malla-wg/internal/noise"
	"github.com/CesarManzoCode/malla-wg/verify/netns"
)

// TestCritKernelReplay is the kernel half of criterion 9: the test drives
// internal/device itself with its own socket in B, captures the datagram
// of one encrypted ICMP echo request and sends it twice. A's wg0
// rx_packets grows by exactly 1 and exactly one echo reply arrives.
func TestCritKernelReplay(t *testing.T) {
	netns.Require(t)
	netns.Run(t, func(t *testing.T) {
		netns.Add(t, "A", "B")
		netns.Veth(t, "A", "ab", "192.168.50.1/24", "B", "ba", "192.168.50.2/24")
		kPriv, kPub := newKeypair(t)
		oPriv, oPub := newKeypair(t)
		k := NewKernel(t, "A", "wg0", "10.200.0.1/24", kPriv, 51820,
			KernelPeer(oPub, [32]byte{}, netip.MustParsePrefix("10.200.0.2/32"), netip.AddrPort{}))
		var conn *net.UDPConn
		if err := netns.Do("B", func() (err error) {
			conn, err = net.ListenUDP("udp4", &net.UDPAddr{Port: 51820})
			return err
		}); err != nil {
			t.Fatalf("socket in B: %v", err)
		}
		defer conn.Close()
		start := time.Now()
		dev, err := device.New(device.Config{
			PrivateKey: oPriv,
			Peers:      []device.PeerConfig{OwnPeer(kPub, [32]byte{}, netip.MustParsePrefix("10.200.0.1/32"), kernelEndpoint)},
			Rand:       rand.Reader,
			WallOffset: start.UnixNano(),
		})
		if err != nil {
			t.Fatal(err)
		}
		d := &direct{t: t, dev: dev, conn: conn, start: start}
		src, dst := netip.MustParseAddr("10.200.0.2"), netip.MustParseAddr("10.200.0.1")

		// The first echo request is staged, starts the handshake and goes
		// out with the new session.
		d.apply(dev.HandleTUN(d.now(), ipv4Packet(src, dst, icmpEcho(8, 0x6d61, 1, pingData))))
		if n := d.replies(1, 3*time.Second); n != 1 {
			t.Fatalf("handshake and first ping: %d replies, want 1; kernel: %s", n, k.State())
		}

		before := rxPackets(t, "A", "wg0")
		out := dev.HandleTUN(d.now(), ipv4Packet(src, dst, icmpEcho(8, 0x6d61, 2, pingData)))
		if len(out.Datagrams) != 1 || noise.MessageType(out.Datagrams[0].Data) != noise.TypeTransport {
			t.Fatalf("the second echo request gave %d datagrams, want one data message", len(out.Datagrams))
		}
		captured := out.Datagrams[0]
		for range 2 {
			if _, err := conn.WriteToUDPAddrPort(captured.Data, captured.Dst); err != nil {
				t.Fatal(err)
			}
		}
		replies := d.replies(2, 3*time.Second)
		after := rxPackets(t, "A", "wg0")
		if after-before != 1 {
			t.Errorf("wg0 rx_packets grew by %d for one data message sent twice, want 1; kernel: %s", after-before, k.State())
		}
		if replies != 1 {
			t.Errorf("%d echo replies to one data message sent twice, want 1; kernel: %s", replies, k.State())
		}
	})
}

// TestCritKernelRekeyLong is the kernel half of criterion 10: 200 s of
// pings every 100 ms from the own node to the kernel (2000), none lost,
// and wgctrl shows a handshake later than second 120 of the run.
func TestCritKernelRekeyLong(t *testing.T) {
	if testing.Short() {
		t.Skip("200 s run, skipped with -short")
	}
	netns.Require(t)
	netns.Run(t, func(t *testing.T) {
		k, o := kernelSetup(t, "", true, [32]byte{}, [32]byte{})
		start := time.Now()
		out, err := netns.Exec("B", "ping", "-q", "-c", "2000", "-i", "0.1", "-W", "2", "10.200.0.1")
		t.Logf("ping 10.200.0.1 from B:\n%s", out)
		sent, received, ok := pingSummary(out)
		if !ok {
			t.Fatalf("no ping summary (%v): %s", err, Failure("own", o, k.State()))
		}
		if sent != 2000 || received != 2000 {
			t.Errorf("%d echo requests sent and %d answered, want 2000 and 2000: %s", sent, received, Failure("own", o, k.State()))
		}
		p, err := k.Peer()
		if err != nil {
			t.Fatalf("wgctrl: %v", err)
		}
		if limit := start.Add(120 * time.Second); !p.LastHandshakeTime.After(limit) {
			t.Errorf("kernel's last handshake at %v, want after %v (second 120): %s",
				p.LastHandshakeTime, limit, Failure("own", o, k.State()))
		}
		t.Logf("own node: %d sessions derived, %d initiations sent",
			o.Events.Count(device.EventHandshake, ""), o.Events.Count(device.EventRekey, ""))
	})
}

// direct drives an internal/device without internal/runtime: the test
// owns its socket and its clock, and no timer fires.
type direct struct {
	t     *testing.T
	dev   *device.Device
	conn  *net.UDPConn
	start time.Time
}

func (d *direct) now() int64 { return int64(time.Since(d.start)) }

// apply sends the datagrams of out and returns its TUN packets.
func (d *direct) apply(out device.Output) [][]byte {
	for _, dg := range out.Datagrams {
		if _, err := d.conn.WriteToUDPAddrPort(dg.Data, dg.Dst); err != nil {
			d.t.Fatalf("send to %v: %v", dg.Dst, err)
		}
	}
	return out.Packets
}

// replies feeds the device every datagram that arrives during wait and
// returns how many echo replies with sequence seq it delivered.
func (d *direct) replies(seq uint16, wait time.Duration) int {
	deadline := time.Now().Add(wait)
	buf := make([]byte, 65535)
	n := 0
	for {
		d.conn.SetReadDeadline(deadline)
		k, src, err := d.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return n // deadline
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		for _, pkt := range d.apply(d.dev.HandleUDP(d.now(), src, bytes.Clone(buf[:k]))) {
			if _, _, msg, ok := parseICMPv4(pkt); ok && isReply(msg, seq) {
				n++
			}
		}
	}
}

// rxPackets reads /sys/class/net/<iface>/statistics/rx_packets in ns;
// `ip netns exec` mounts the namespace's own sysfs.
func rxPackets(t *testing.T, ns, iface string) uint64 {
	t.Helper()
	out := netns.MustExec(t, ns, "cat", "/sys/class/net/"+iface+"/statistics/rx_packets")
	n, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		t.Fatalf("rx_packets of %s in %s: %q: %v", iface, ns, out, err)
	}
	return n
}

var pingStats = regexp.MustCompile(`(\d+) packets transmitted, (\d+) received`)

// pingSummary parses the statistics line of ping(8).
func pingSummary(out []byte) (sent, received int, ok bool) {
	m := pingStats.FindSubmatch(out)
	if m == nil {
		return 0, 0, false
	}
	sent, _ = strconv.Atoi(string(m[1]))
	received, _ = strconv.Atoi(string(m[2]))
	return sent, received, true
}

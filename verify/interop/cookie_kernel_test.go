//go:build linux

package interop

import (
	"net"
	"testing"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/device"
	"github.com/CesarManzoCode/malla-wg/verify/netns"
)

// TestCritCookieKernel is the kernel half of criterion 8 (cookies). (a)
// The kernel as responder under load: from B, FloodSize initiations with
// a valid mac1 for the kernel's key reach A in under 1 s while the own
// node starts a real handshake; the own node accepts a cookie reply,
// retries with mac2 and its ping is answered. (b) The own node as
// responder with ForceUnderLoad and the kernel as initiator: the kernel
// gets the cookie, retries with mac2 and its ping is answered.
func TestCritCookieKernel(t *testing.T) {
	netns.Require(t)
	netns.Run(t, func(t *testing.T) {
		t.Run("kernel-under-load", func(t *testing.T) {
			k, o := kernelSetup(t, "1", true, [32]byte{}, [32]byte{})
			// The flood leaves from a second address of B: past 2048
			// queued handshakes the kernel rate-limits each source IP,
			// and the own node's initiation must not share its bucket.
			netns.MustExec(t, "B1", "ip", "addr", "add", "192.168.50.3/24", "dev", "ba1")
			pub, err := k.PublicKey()
			if err != nil {
				t.Fatalf("wgctrl: %v", err)
			}
			msg := FloodInitiation(t, pub)
			conns := make([]*net.UDPConn, 4)
			var trig *net.UDPConn
			if err := netns.Do("B1", func() error {
				for i := range conns {
					c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(192, 168, 50, 3)})
					if err != nil {
						return err
					}
					t.Cleanup(func() { c.Close() })
					conns[i] = c
				}
				// Any datagram to the kernel's tunnel address goes
				// through malla0 and starts the own node's handshake.
				c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(10, 200, 0, 1), Port: 9})
				trig = c
				return err
			}); err != nil {
				t.Fatalf("flood sockets in B1: %v", err)
			}
			t.Cleanup(func() { trig.Close() })
			took := Flood(t, conns, kernelEndpoint, msg, func() {
				if _, err := trig.Write([]byte("cookie")); err != nil {
					t.Errorf("trigger: %v", err)
				}
			})
			if took >= time.Second {
				t.Errorf("the flood of %d initiations took %v, want under 1 s", FloodSize, took)
			}
			if !o.Events.Wait(device.EventCookie, "", 3*time.Second) {
				t.Fatalf("the own node accepted no cookie reply: %s", Failure("own", o, k.State()))
			}
			if out, err := netns.Exec("B1", "ping", "-c", "3", "-w", "20", "10.200.0.1"); err != nil {
				t.Fatalf("ping after the cookie: %v\n%s", err, Failure("own", o, k.State()))
			} else {
				t.Logf("ping 10.200.0.1 from B1:\n%s", out)
			}
			if err := CookieRetry(o); err != nil {
				t.Errorf("%v: %s", err, Failure("own", o, k.State()))
			}
			if p, err := k.Peer(); err != nil || p.LastHandshakeTime.IsZero() {
				t.Errorf("kernel shows no handshake (%v): %s", err, Failure("own", o, k.State()))
			}
		})
		t.Run("own-under-load", func(t *testing.T) {
			k, o := kernelSetup(t, "2", false, [32]byte{}, [32]byte{}, UnderLoad)
			// The kernel retries REKEY_TIMEOUT (5 s) after the cookie,
			// so the ping gets a deadline instead of `-W 2` alone.
			if out, err := netns.Exec("A2", "ping", "-c", "3", "-w", "20", "10.200.0.2"); err != nil {
				t.Fatalf("ping from the kernel: %v\n%s", err, Failure("kernel", o, k.State()))
			} else {
				t.Logf("ping 10.200.0.2 from A2:\n%s", out)
			}
			if o.Events.Count(device.EventDrop, device.ReasonCookie) == 0 {
				t.Errorf("the own node under load sent no cookie reply: %s", Failure("kernel", o, k.State()))
			}
			if hs, ok := o.Events.Handshake(); !ok || hs != "responder" {
				t.Errorf("own node handshake role %q, want responder: %s", hs, Failure("kernel", o, k.State()))
			}
			if p, err := k.Peer(); err != nil || p.LastHandshakeTime.IsZero() {
				t.Errorf("kernel shows no handshake (%v): %s", err, Failure("kernel", o, k.State()))
			}
		})
	})
}

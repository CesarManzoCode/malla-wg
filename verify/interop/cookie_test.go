package interop

import (
	"net"
	"testing"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/device"
)

// TestCritCookieWireGuardGo is the wireguard-go half of criterion 8
// (cookies), on 127.0.0.1 without privileges. (a) wireguard-go as
// responder under load: FloodSize initiations with a valid mac1 reach it
// in under 1 s (it is under load from 128 queued handshakes) while the
// own node starts a real handshake; the own node accepts a cookie reply,
// retries with mac2 and its ping is answered. (b) The own node as
// responder with ForceUnderLoad: wireguard-go gets the cookie, retries
// with mac2 and its ping is answered.
func TestCritCookieWireGuardGo(t *testing.T) {
	t.Run("wireguard-go-under-load", func(t *testing.T) {
		w, o := wggoSetup(t, true, [32]byte{}, [32]byte{})
		msg := FloodInitiation(t, w.Public)
		conns := make([]*net.UDPConn, 4)
		for i := range conns {
			c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close() })
			conns[i] = c
		}
		took := Flood(t, conns, w.Endpoint(), msg, func() {
			if err := o.Send(wgAddr); err != nil {
				t.Errorf("own node: %v", err)
			}
		})
		if took >= time.Second {
			t.Errorf("the flood of %d initiations took %v, want under 1 s", FloodSize, took)
		}
		if !o.Events.Wait(device.EventCookie, "", 3*time.Second) {
			t.Fatalf("the own node accepted no cookie reply: %s", Failure("own", o, w.State()))
		}
		if err := o.Ping(wgAddr, 10); err != nil {
			t.Fatalf("ping after the cookie: %v\n%s", err, Failure("own", o, w.State()))
		}
		if err := CookieRetry(o); err != nil {
			t.Errorf("%v: %s", err, Failure("own", o, w.State()))
		}
		if !w.Handshaked() {
			t.Errorf("wireguard-go shows no handshake: %s", Failure("own", o, w.State()))
		}
	})
	t.Run("own-under-load", func(t *testing.T) {
		w, o := wggoSetup(t, false, [32]byte{}, [32]byte{}, UnderLoad)
		if err := w.Ping(ownAddr, 10); err != nil {
			t.Fatalf("ping from wireguard-go: %v\n%s", err, Failure("wireguard-go", o, w.State()))
		}
		if o.Events.Count(device.EventDrop, device.ReasonCookie) == 0 {
			t.Errorf("the own node under load sent no cookie reply: %s", Failure("wireguard-go", o, w.State()))
		}
		if hs, ok := o.Events.Handshake(); !ok || hs != "responder" {
			t.Errorf("own node handshake role %q, want responder: %s", hs, Failure("wireguard-go", o, w.State()))
		}
		if !w.Handshaked() {
			t.Errorf("wireguard-go shows no handshake: %s", Failure("wireguard-go", o, w.State()))
		}
	})
}

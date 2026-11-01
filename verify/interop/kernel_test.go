//go:build linux

package interop

import (
	"net/netip"
	"testing"

	"github.com/CesarManzoCode/malla-wg/internal/device"
	"github.com/CesarManzoCode/malla-wg/verify/netns"
)

// TestCritKernelOwnInitiator is criterion 5: namespaces A (kernel) and B
// (own node); only B knows the other's endpoint, so B initiates. A ping
// from B to A's tunnel address is answered and wgctrl shows a handshake.
func TestCritKernelOwnInitiator(t *testing.T) {
	netns.Require(t)
	netns.Run(t, func(t *testing.T) {
		k, o := kernelSetup(t, "", true, [32]byte{}, [32]byte{})
		kernelPing(t, k, o, true)
	})
}

// TestCritKernelOwnResponder is criterion 6: the own node has no endpoint
// for the kernel, so the kernel initiates with `ping -c 3 -W 2` from A.
func TestCritKernelOwnResponder(t *testing.T) {
	netns.Require(t)
	netns.Run(t, func(t *testing.T) {
		k, o := kernelSetup(t, "", false, [32]byte{}, [32]byte{})
		kernelPing(t, k, o, false)
	})
}

// TestCritPSKKernel is the kernel half of criterion 8 (PSK): both
// directions with the same preshared key on both sides, then a run with
// different keys that must not complete the handshake.
func TestCritPSKKernel(t *testing.T) {
	netns.Require(t)
	netns.Run(t, func(t *testing.T) {
		psk := newKey(t)
		t.Run("own-initiator", func(t *testing.T) {
			k, o := kernelSetup(t, "1", true, psk, psk)
			kernelPing(t, k, o, true)
		})
		t.Run("kernel-initiator", func(t *testing.T) {
			k, o := kernelSetup(t, "2", false, psk, psk)
			kernelPing(t, k, o, false)
		})
		t.Run("mismatch", func(t *testing.T) {
			k, o := kernelSetup(t, "3", true, psk, newKey(t))
			if out, err := netns.Exec("B3", "ping", "-c", "2", "-W", "2", "10.200.0.1"); err == nil {
				t.Errorf("ping with different PSKs was answered:\n%s\n%s", out, Failure("own", o, k.State()))
			}
			if p, err := k.Peer(); err != nil || !p.LastHandshakeTime.IsZero() {
				t.Errorf("kernel completed a handshake with different PSKs (%v): %s", err, Failure("own", o, k.State()))
			}
			if hs, ok := o.Events.Handshake(); ok {
				t.Errorf("own node derived a session as %s with different PSKs: %s", hs, Failure("own", o, k.State()))
			}
		})
	})
}

// kernelEndpoint is where the kernel link of kernelSetup listens.
var kernelEndpoint = netip.MustParseAddrPort("192.168.50.1:51820")

// kernelSetup builds namespaces A<id> (kernel link wg0, 10.200.0.1) and
// B<id> (own node, 10.200.0.2) joined by a veth on 192.168.50.0/24. Only
// the initiating side gets the other's endpoint; mods adjust the own
// node's device configuration.
func kernelSetup(t *testing.T, id string, ownInitiates bool, kernelPSK, ownPSK [32]byte, mods ...func(*device.Config)) (*Kernel, *Own) {
	t.Helper()
	a, b := "A"+id, "B"+id
	netns.Add(t, a, b)
	netns.Veth(t, a, "ab"+id, "192.168.50.1/24", b, "ba"+id, "192.168.50.2/24")
	kPriv, kPub := newKeypair(t)
	oPriv, oPub := newKeypair(t)
	var kEnd, oEnd netip.AddrPort
	if ownInitiates {
		oEnd = kernelEndpoint
	} else {
		kEnd = netip.MustParseAddrPort("192.168.50.2:51820")
	}
	k := NewKernel(t, a, "wg0", "10.200.0.1/24", kPriv, 51820,
		KernelPeer(oPub, kernelPSK, netip.MustParsePrefix("10.200.0.2/32"), kEnd))
	o := NewOwnNetns(t, b, "10.200.0.2/24", 51820, oPriv,
		OwnPeer(kPub, ownPSK, netip.MustParsePrefix("10.200.0.1/32"), oEnd), mods...)
	return k, o
}

// kernelPing pings across the tunnel from the initiating side and checks
// that the kernel shows a handshake and the own node derived its session
// in the expected role.
func kernelPing(t *testing.T, k *Kernel, o *Own, ownInitiates bool) {
	t.Helper()
	initiator, from, dst, role := "kernel", k.NS, "10.200.0.2", "responder"
	if ownInitiates {
		initiator, from, dst, role = "own", "B"+k.NS[1:], "10.200.0.1", "initiator"
	}
	if out, err := netns.Exec(from, "ping", "-c", "3", "-W", "2", dst); err != nil {
		t.Fatalf("ping %s from %s: %v\n%s", dst, from, err, Failure(initiator, o, k.State()))
	} else {
		t.Logf("ping %s from %s:\n%s", dst, from, out)
	}
	if p, err := k.Peer(); err != nil || p.LastHandshakeTime.IsZero() {
		t.Errorf("kernel shows no handshake (%v): %s", err, Failure(initiator, o, k.State()))
	}
	if hs, ok := o.Events.Handshake(); !ok || hs != role {
		t.Errorf("own node handshake role %q, want %q: %s", hs, role, Failure(initiator, o, k.State()))
	}
}

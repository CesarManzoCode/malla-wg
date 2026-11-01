package interop

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/CesarManzoCode/malla-wg/internal/device"
)

var (
	wgAddr  = netip.MustParseAddr("10.200.0.1")
	ownAddr = netip.MustParseAddr("10.200.0.2")
)

// TestCritWireGuardGoOwnInitiator is the first half of criterion 7: only
// the own node knows wireguard-go's endpoint, so it initiates; its ping
// to wireguard-go's netstack is answered.
func TestCritWireGuardGoOwnInitiator(t *testing.T) {
	w, o := wggoSetup(t, true, [32]byte{}, [32]byte{})
	wggoPing(t, w, o, true)
}

// TestCritWireGuardGoOwnResponder is the second half of criterion 7:
// wireguard-go initiates and its ping4 socket gets an answer from the own
// node's in-memory TUN.
func TestCritWireGuardGoOwnResponder(t *testing.T) {
	w, o := wggoSetup(t, false, [32]byte{}, [32]byte{})
	wggoPing(t, w, o, false)
}

// TestCritPSKWireGuardGo is the wireguard-go half of criterion 8 (PSK):
// both directions with the same preshared key, then a run with different
// keys that must not complete the handshake.
func TestCritPSKWireGuardGo(t *testing.T) {
	psk := newKey(t)
	t.Run("own-initiator", func(t *testing.T) {
		w, o := wggoSetup(t, true, psk, psk)
		wggoPing(t, w, o, true)
	})
	t.Run("wireguard-go-initiator", func(t *testing.T) {
		w, o := wggoSetup(t, false, psk, psk)
		wggoPing(t, w, o, false)
	})
	t.Run("mismatch", func(t *testing.T) {
		w, o := wggoSetup(t, true, psk, newKey(t))
		if err := o.Ping(wgAddr, 2); err == nil {
			t.Errorf("ping with different PSKs was answered: %s", Failure("own", o, w.State()))
		}
		if w.Handshaked() {
			t.Errorf("wireguard-go completed a handshake with different PSKs: %s", Failure("own", o, w.State()))
		}
		if hs, ok := o.Events.Handshake(); ok {
			t.Errorf("own node derived a session as %s with different PSKs: %s", hs, Failure("own", o, w.State()))
		}
	})
}

// wggoSetup starts wireguard-go (10.200.0.1) and the own node (10.200.0.2)
// on 127.0.0.1; only the initiating side gets the other's endpoint. mods
// adjust the own node's device configuration.
func wggoSetup(t *testing.T, ownInitiates bool, wgPSK, ownPSK [32]byte, mods ...func(*device.Config)) (*WGGo, *Own) {
	t.Helper()
	wPriv, wPub := newKeypair(t)
	oPriv, oPub := newKeypair(t)
	wgPrefix, ownPrefix := netip.PrefixFrom(wgAddr, 32), netip.PrefixFrom(ownAddr, 32)
	if ownInitiates {
		w := NewWGGo(t, wPriv, wgAddr, oPub, wgPSK, ownPrefix, netip.AddrPort{})
		return w, NewOwnMem(t, oPriv, ownAddr, OwnPeer(wPub, ownPSK, wgPrefix, w.Endpoint()), mods...)
	}
	o := NewOwnMem(t, oPriv, ownAddr, OwnPeer(wPub, ownPSK, wgPrefix, netip.AddrPort{}), mods...)
	return NewWGGo(t, wPriv, wgAddr, oPub, wgPSK, ownPrefix, o.Node.LocalAddr()), o
}

// wggoPing pings across the tunnel from the initiating side and checks
// that wireguard-go shows a handshake and the own node derived its
// session in the expected role.
func wggoPing(t *testing.T, w *WGGo, o *Own, ownInitiates bool) {
	t.Helper()
	initiator, role, err := "wireguard-go", "responder", error(nil)
	if ownInitiates {
		initiator, role = "own", "initiator"
		err = o.Ping(wgAddr, 3)
	} else {
		err = w.Ping(ownAddr, 3)
	}
	if err != nil {
		t.Fatalf("ping from %s: %v\n%s", initiator, err, Failure(initiator, o, w.State()))
	}
	if !w.Handshaked() {
		t.Errorf("wireguard-go shows no handshake: %s", Failure(initiator, o, w.State()))
	}
	if hs, ok := o.Events.Handshake(); !ok || hs != role {
		t.Errorf("own node handshake role %q, want %q: %s", hs, role, Failure(initiator, o, w.State()))
	}
}

// newKeypair generates a WireGuard key pair with wgtypes, an independent
// implementation of the public key derivation.
func newKeypair(t testing.TB) (priv, pub [32]byte) {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k, k.PublicKey()
}

// newKey returns 32 random bytes, used as a preshared key.
func newKey(t testing.TB) [32]byte {
	t.Helper()
	k, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

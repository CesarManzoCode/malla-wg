package interop

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WGGo is a wireguard-go device in this process, on a tun/netstack TUN and
// conn.NewDefaultBind, listening on a free port.
type WGGo struct {
	Dev  *wgdevice.Device
	Net  *netstack.Net
	Addr netip.Addr // tunnel address
	Port uint16
	// Public is the static public key, derived with wgtypes.
	Public [32]byte
}

// NewWGGo starts wireguard-go with one peer until t ends; an invalid
// endpoint leaves the peer's endpoint unknown.
func NewWGGo(t testing.TB, priv [32]byte, addr netip.Addr, peerPub, psk [32]byte, allowed netip.Prefix, endpoint netip.AddrPort) *WGGo {
	t.Helper()
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, 1420)
	if err != nil {
		t.Fatalf("netstack: %v", err)
	}
	dev := wgdevice.NewDevice(tdev, conn.NewDefaultBind(), wgdevice.NewLogger(wgdevice.LogLevelError, "wireguard-go: "))
	t.Cleanup(dev.Close)
	cfg := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\npreshared_key=%s\nallowed_ip=%s\n",
		hex.EncodeToString(priv[:]), hex.EncodeToString(peerPub[:]), hex.EncodeToString(psk[:]), allowed)
	if endpoint.IsValid() {
		cfg += "endpoint=" + endpoint.String() + "\n"
	}
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatalf("wireguard-go config: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("wireguard-go up: %v", err)
	}
	w := &WGGo{Dev: dev, Net: tnet, Addr: addr, Public: wgtypes.Key(priv).PublicKey()}
	port, err := strconv.ParseUint(w.field("listen_port"), 10, 16)
	if err != nil || port == 0 {
		t.Fatalf("wireguard-go listen_port: %q %v", w.field("listen_port"), err)
	}
	w.Port = uint16(port)
	return w
}

// Endpoint is the address the own node reaches wireguard-go at.
func (w *WGGo) Endpoint() netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), w.Port)
}

// field returns the first value of key in the UAPI state.
func (w *WGGo) field(key string) string {
	state, _ := w.Dev.IpcGet()
	for _, line := range strings.Split(state, "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return v
		}
	}
	return ""
}

// Handshaked reports whether wireguard-go has a non-zero last handshake
// time for its peer.
func (w *WGGo) Handshaked() bool {
	s := w.field("last_handshake_time_sec")
	return s != "" && s != "0"
}

// State is wireguard-go's UAPI state without its keys.
func (w *WGGo) State() string {
	state, err := w.Dev.IpcGet()
	if err != nil {
		return "IpcGet: " + err.Error()
	}
	var b strings.Builder
	for _, line := range strings.Split(state, "\n") {
		if !strings.HasPrefix(line, "private_key=") && !strings.HasPrefix(line, "preshared_key=") {
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

// Ping sends up to tries echo requests from netstack (a ping4 socket) to
// dst and returns nil at the first reply.
func (w *WGGo) Ping(dst netip.Addr, tries int) error {
	pc, err := w.Net.DialPingAddr(w.Addr, dst)
	if err != nil {
		return err
	}
	defer pc.Close()
	buf := make([]byte, 1500)
	for seq := 1; seq <= tries; seq++ {
		pc.SetDeadline(time.Now().Add(pingTimeout))
		if _, err := pc.Write(icmpEcho(8, 0, uint16(seq), pingData)); err != nil {
			return err
		}
		for {
			n, err := pc.Read(buf)
			if err != nil {
				break // deadline
			}
			if isReply(buf[:n], uint16(seq)) {
				return nil
			}
		}
	}
	return fmt.Errorf("no echo reply from %s to %d requests", dst, tries)
}

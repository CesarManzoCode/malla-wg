//go:build linux

package interop

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/CesarManzoCode/malla-wg/internal/device"
	"github.com/CesarManzoCode/malla-wg/internal/tun"
	"github.com/CesarManzoCode/malla-wg/verify/netns"
)

// Kernel is a kernel WireGuard link inside a namespace.
type Kernel struct {
	NS, Iface string
	client    *wgctrl.Client
}

// KernelPeer is the wgctrl configuration of the kernel's only peer; an
// invalid endpoint leaves it unknown.
func KernelPeer(pub, psk [32]byte, allowed netip.Prefix, endpoint netip.AddrPort) wgtypes.PeerConfig {
	key := wgtypes.Key(psk)
	p := wgtypes.PeerConfig{
		PublicKey:         wgtypes.Key(pub),
		PresharedKey:      &key,
		ReplaceAllowedIPs: true,
		AllowedIPs:        []net.IPNet{{IP: allowed.Addr().AsSlice(), Mask: net.CIDRMask(allowed.Bits(), allowed.Addr().BitLen())}},
	}
	if endpoint.IsValid() {
		p.Endpoint = net.UDPAddrFromAddrPort(endpoint)
	}
	return p
}

// NewKernel creates link iface in ns with address addr (prefix notation),
// configures key, port and peer with wgctrl and brings it up. The wgctrl
// netlink socket is created inside ns (netns.Do), so it talks to ns.
func NewKernel(t testing.TB, ns, iface, addr string, priv [32]byte, port int, peer wgtypes.PeerConfig) *Kernel {
	t.Helper()
	netns.MustExec(t, ns, "ip", "link", "add", iface, "type", "wireguard")
	netns.MustExec(t, ns, "ip", "addr", "add", addr, "dev", iface)
	k := &Kernel{NS: ns, Iface: iface}
	if err := netns.Do(ns, func() (err error) { k.client, err = wgctrl.New(); return err }); err != nil {
		t.Fatalf("wgctrl in %s: %v", ns, err)
	}
	t.Cleanup(func() { k.client.Close() })
	key := wgtypes.Key(priv)
	if err := k.client.ConfigureDevice(iface, wgtypes.Config{
		PrivateKey: &key, ListenPort: &port, ReplacePeers: true, Peers: []wgtypes.PeerConfig{peer},
	}); err != nil {
		t.Fatalf("wgctrl configure %s in %s: %v", iface, ns, err)
	}
	netns.MustExec(t, ns, "ip", "link", "set", iface, "up")
	return k
}

// Peer reads the kernel's only peer.
func (k *Kernel) Peer() (wgtypes.Peer, error) {
	d, err := k.client.Device(k.Iface)
	if err != nil {
		return wgtypes.Peer{}, err
	}
	if len(d.Peers) != 1 {
		return wgtypes.Peer{}, fmt.Errorf("%s has %d peers, want 1", k.Iface, len(d.Peers))
	}
	return d.Peers[0], nil
}

// State describes the kernel's peer as wgctrl reads it.
func (k *Kernel) State() string {
	p, err := k.Peer()
	if err != nil {
		return "wgctrl: " + err.Error()
	}
	return fmt.Sprintf("endpoint=%v last_handshake=%v rx=%d tx=%d", p.Endpoint, p.LastHandshakeTime, p.ReceiveBytes, p.TransmitBytes)
}

// NewOwnNetns runs an own node in ns on a Linux TUN named malla0 with
// address addr (prefix notation, MTU 1420) and a UDP socket on port.
func NewOwnNetns(t testing.TB, ns, addr string, port int, priv [32]byte, peer device.PeerConfig) *Own {
	t.Helper()
	prefix := netip.MustParsePrefix(addr)
	var conn *net.UDPConn
	var dev tun.Device
	if err := netns.Do(ns, func() (err error) {
		if conn, err = net.ListenUDP("udp4", &net.UDPAddr{Port: port}); err != nil {
			return err
		}
		if dev, err = tun.OpenLinux("malla0"); err != nil {
			conn.Close()
		}
		return err
	}); err != nil {
		t.Fatalf("own node in %s: %v", ns, err)
	}
	o := startOwn(t, priv, prefix.Addr(), peer, conn, dev)
	netns.MustExec(t, ns, "ip", "addr", "add", addr, "dev", "malla0")
	netns.MustExec(t, ns, "ip", "link", "set", "malla0", "mtu", "1420", "up")
	return o
}

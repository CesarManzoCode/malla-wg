package device

import (
	"errors"
	"net/netip"
	"slices"

	"github.com/CesarManzoCode/malla-wg/internal/noise"
)

// AddPeer adds a peer, as New does for each configured one. The mesh calls
// it when the coordination's map brings a new peer.
func (d *Device) AddPeer(pc PeerConfig) error {
	if _, dup := d.byKey[pc.PublicKey]; dup {
		return errors.New("duplicate public key")
	}
	if pc.PersistentKeepalive < 0 {
		return errors.New("negative persistent keepalive")
	}
	for _, pfx := range pc.AllowedIPs {
		if !pfx.IsValid() {
			return errors.New("invalid allowed IP prefix")
		}
	}
	np, err := d.local.NewPeer(pc.PublicKey, pc.PresharedKey)
	if err != nil {
		return err
	}
	p := &peer{
		key:        pc.PublicKey,
		noise:      np,
		endpoint:   pc.Endpoint,
		persistent: int64(pc.PersistentKeepalive),
	}
	for _, pfx := range pc.AllowedIPs {
		d.routes.insert(pfx, p)
	}
	d.peers = append(d.peers, p)
	d.byKey[p.key] = p
	return nil
}

// RemovePeer forgets the peer with public key pub: its keypairs, the
// handshake in flight, its staged packets and its allowed IPs. Afterwards
// its initiations fail the lookup and its data messages carry unknown
// indices, so nothing from it reaches the TUN. It reports whether the
// peer existed.
func (d *Device) RemovePeer(pub [noise.KeySize]byte) bool {
	p := d.byKey[pub]
	if p == nil {
		return false
	}
	d.clearKeys(p)
	d.routes.remove(p)
	d.peers = slices.DeleteFunc(d.peers, func(q *peer) bool { return q == p })
	delete(d.byKey, pub)
	return true
}

// SetEndpoint replaces the endpoint of the peer with public key pub and
// reports whether the peer exists. Roaming may change it again later.
func (d *Device) SetEndpoint(pub [noise.KeySize]byte, ep netip.AddrPort) bool {
	p := d.byKey[pub]
	if p == nil {
		return false
	}
	p.endpoint = ep
	return true
}

// Peers returns the public keys of the peers, in the order they were added.
func (d *Device) Peers() [][noise.KeySize]byte {
	keys := make([][noise.KeySize]byte, len(d.peers))
	for i, p := range d.peers {
		keys[i] = p.key
	}
	return keys
}

package device

import (
	"errors"
	"net/netip"

	"github.com/CesarManzoCode/malla-wg/internal/noise"
)

// checkMACs verifies mac1 and, under load, mac2. Without a valid mac2 it
// answers src with a cookie reply.
func (d *Device) checkMACs(now int64, src netip.AddrPort, b []byte) bool {
	if !d.local.CheckMAC1(b) {
		d.drop(nil, ReasonMAC1)
		return false
	}
	if !d.underLoad(now) {
		return true
	}
	ok, err := d.local.CheckMAC2(b, src, now, d.rnd)
	if err != nil {
		d.drop(nil, ReasonRandom)
		return false
	}
	if ok {
		return true
	}
	if r, err := d.local.CreateCookieReply(b, src, now, d.rnd); err == nil {
		rb, _ := r.MarshalBinary()
		d.send(src, rb)
	}
	d.drop(nil, ReasonCookie)
	return false
}

func (d *Device) lookupNoise(static [noise.KeySize]byte) *noise.Peer {
	if p := d.byKey[static]; p != nil {
		return p.noise
	}
	return nil
}

// handleInitiation answers a valid initiation and keeps the new keypair in
// next until the initiator's first data message arrives.
func (d *Device) handleInitiation(now int64, src netip.AddrPort, b []byte) {
	if !d.checkMACs(now, src, b) {
		return
	}
	var m noise.Initiation
	if err := m.UnmarshalBinary(b); err != nil {
		d.drop(nil, ReasonHandshake)
		return
	}
	np, err := d.local.ConsumeInitiation(&m, now, d.lookupNoise)
	if err != nil {
		d.drop(nil, ReasonHandshake)
		return
	}
	p := d.byKey[np.PublicKey()]
	// Consuming the initiation replaced any initiation of ours in flight.
	d.dropHandshakeIndex(p)
	d.anyAuthenticatedPacketReceived(p)
	d.anyAuthenticatedPacketTraversal(now, p)
	d.setEndpoint(p, src)

	idx, ok := d.newIndex()
	if !ok {
		return
	}
	r, err := p.noise.CreateResponse(d.rnd, now, idx)
	if err != nil {
		d.drop(p, ReasonRandom)
		return
	}
	nk, err := p.noise.BeginSession()
	if err != nil {
		d.drop(p, ReasonHandshake)
		return
	}
	k := &keypair{Keypair: nk, birth: now}
	d.indices[idx] = indexEntry{peer: p, kp: k}
	d.addKeypair(p, k)
	d.sessionDerived(now, p)
	d.event(EventHandshake, p, "responder")

	rb, _ := r.MarshalBinary()
	d.send(p.endpoint, rb)
	d.anyAuthenticatedPacketTraversal(now, p)
	d.anyAuthenticatedPacketSent(p)
}

// handleResponse completes the handshake as initiator: the new keypair
// becomes current at once and the staged packets, or a keepalive, go out.
func (d *Device) handleResponse(now int64, src netip.AddrPort, b []byte) {
	if !d.checkMACs(now, src, b) {
		return
	}
	var m noise.Response
	if err := m.UnmarshalBinary(b); err != nil {
		d.drop(nil, ReasonHandshake)
		return
	}
	e, ok := d.indices[m.Receiver]
	if !ok || e.kp != nil {
		d.drop(nil, ReasonIndex)
		return
	}
	p := e.peer
	if err := p.noise.ConsumeResponse(&m); err != nil {
		d.drop(p, ReasonHandshake)
		return
	}
	nk, err := p.noise.BeginSession()
	if err != nil {
		d.drop(p, ReasonHandshake)
		return
	}
	d.anyAuthenticatedPacketReceived(p)
	d.anyAuthenticatedPacketTraversal(now, p)
	d.setEndpoint(p, src)

	k := &keypair{Keypair: nk, birth: now}
	d.indices[m.Receiver] = indexEntry{peer: p, kp: k}
	p.hsPending = false
	d.addKeypair(p, k)
	d.sessionDerived(now, p)
	d.handshakeComplete(p)
	d.event(EventHandshake, p, "initiator")
	d.sendKeepalive(now, p)
}

func (d *Device) handleCookieReply(now int64, b []byte) {
	var r noise.CookieReply
	if err := r.UnmarshalBinary(b); err != nil {
		d.drop(nil, ReasonCookieReply)
		return
	}
	e, ok := d.indices[r.Receiver]
	if !ok {
		d.drop(nil, ReasonIndex)
		return
	}
	if err := e.peer.noise.ConsumeCookieReply(&r, now); err != nil {
		d.drop(e.peer, ReasonCookieReply)
		return
	}
	d.event(EventCookie, e.peer, "")
}

// handleTransport decrypts a data message. Only a message that passes the
// AEAD and the replay window moves the endpoint (D07), and its inner
// source must be in the allowed IPs of the peer that decrypted it.
func (d *Device) handleTransport(now int64, src netip.AddrPort, b []byte) {
	var m noise.Transport
	if err := m.UnmarshalBinary(b); err != nil {
		d.drop(nil, ReasonType)
		return
	}
	e, ok := d.indices[m.Receiver]
	if !ok || e.kp == nil {
		d.drop(nil, ReasonIndex)
		return
	}
	p, k := e.peer, e.kp
	if keypairExpired(k, now) {
		d.drop(p, ReasonExpired)
		return
	}
	plain, err := k.Decrypt(nil, &m)
	if errors.Is(err, noise.ErrReplay) {
		d.drop(p, ReasonReplay)
		return
	}
	if err != nil {
		d.drop(p, ReasonDecrypt)
		return
	}
	d.setEndpoint(p, src)
	if d.receivedWithKeypair(p, k) {
		d.handshakeComplete(p)
		d.sendStaged(now, p)
	}
	d.keepKeyFreshReceiving(now, p)
	d.anyAuthenticatedPacketReceived(p)
	d.anyAuthenticatedPacketTraversal(now, p)
	if len(plain) == 0 {
		return // keepalive
	}
	pkt, inner, _, ok := parseIP(plain)
	if !ok {
		d.drop(p, ReasonInvalid)
		return
	}
	if d.routes.lookup(inner) != p {
		d.drop(p, ReasonAllowedIPs)
		return
	}
	d.dataReceived(now, p)
	d.out.Packets = append(d.out.Packets, pkt)
}

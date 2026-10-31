package device

// Timer hooks with the names and effects of the kernel's timers.c.

func (d *Device) handshakeInitiated(now int64, p *peer) {
	p.retransmit.arm(now + RekeyTimeout + d.jitter())
}

func (d *Device) handshakeComplete(p *peer) {
	p.retransmit.stop()
}

func (d *Device) sessionDerived(now int64, p *peer) {
	p.zeroKeys.arm(now + ZeroKeyMaterialTime)
}

func (d *Device) dataSent(now int64, p *peer) {
	if !p.newHandshake.on {
		p.newHandshake.arm(now + KeepaliveTimeout + RekeyTimeout + d.jitter())
	}
}

func (d *Device) dataReceived(now int64, p *peer) {
	if !p.keepalive.on {
		p.keepalive.arm(now + KeepaliveTimeout)
	} else {
		p.needAnotherKeepalive = true
	}
}

func (d *Device) anyAuthenticatedPacketSent(p *peer) {
	p.keepalive.stop()
}

func (d *Device) anyAuthenticatedPacketReceived(p *peer) {
	p.newHandshake.stop()
}

func (d *Device) anyAuthenticatedPacketTraversal(now int64, p *peer) {
	if p.persistent > 0 {
		p.persistentKA.arm(now + p.persistent)
	}
}

// fireTimers runs the expired timers of p in a fixed order.
func (d *Device) fireTimers(now int64, p *peer) {
	if p.retransmit.due(now) {
		d.retransmitExpired(now, p)
	}
	if p.keepalive.due(now) {
		d.sendKeepalive(now, p)
		if p.needAnotherKeepalive {
			p.needAnotherKeepalive = false
			p.keepalive.arm(now + KeepaliveTimeout)
		}
	}
	if p.newHandshake.due(now) {
		d.sendInitiation(now, p, false, RekeyNoReply)
	}
	if p.zeroKeys.due(now) {
		d.clearKeys(p)
	}
	if p.persistentKA.due(now) && p.persistent > 0 {
		d.sendKeepalive(now, p)
	}
}

// retransmitExpired retries the initiation, or gives up once
// REKEY_ATTEMPT_TIME has passed since the attempt began: the staged
// packets are dropped and the keys erased later.
func (d *Device) retransmitExpired(now int64, p *peer) {
	if now-p.attemptStart >= RekeyAttemptTime {
		p.keepalive.stop()
		p.staged = nil
		if !p.zeroKeys.on {
			p.zeroKeys.arm(now + ZeroKeyMaterialTime)
		}
		d.drop(p, ReasonHandshakeTimeout)
		return
	}
	d.sendInitiation(now, p, true, RekeyRetry)
}

// sendInitiation sends a new initiation to p, at most one per
// REKEY_TIMEOUT. A call that is not a retry starts a new attempt.
func (d *Device) sendInitiation(now int64, p *peer, retry bool, reason string) {
	if !retry {
		p.attemptStart = now
	}
	if !p.endpoint.IsValid() {
		return
	}
	if p.sentInitiation && now-p.lastInitiation < RekeyTimeout {
		return
	}
	idx, ok := d.newIndex()
	if !ok {
		return
	}
	m, err := p.noise.CreateInitiation(d.rnd, now, now+d.wallOffset, idx)
	if err != nil {
		d.drop(p, ReasonRandom)
		return
	}
	d.dropHandshakeIndex(p)
	d.indices[idx] = indexEntry{peer: p}
	p.hsIndex, p.hsPending = idx, true
	p.lastInitiation, p.sentInitiation = now, true

	b, _ := m.MarshalBinary()
	d.send(p.endpoint, b)
	d.event(EventRekey, p, reason)
	d.anyAuthenticatedPacketTraversal(now, p)
	d.anyAuthenticatedPacketSent(p)
	d.handshakeInitiated(now, p)
}

// sendKeepalive sends the staged packets, or an empty one if none.
func (d *Device) sendKeepalive(now int64, p *peer) {
	if len(p.staged) == 0 {
		p.staged = append(p.staged, nil)
	}
	d.sendStaged(now, p)
}

// sendStaged encrypts the staged packets with the current keypair. Without
// a usable one they stay staged and a handshake starts.
func (d *Device) sendStaged(now int64, p *peer) {
	if len(p.staged) == 0 || !p.endpoint.IsValid() {
		return
	}
	k := p.current
	if !canSend(k, now) {
		d.sendInitiation(now, p, false, RekeyNoKeypair)
		return
	}
	data := false
	for len(p.staged) > 0 {
		pkt := p.staged[0]
		m, err := k.Encrypt(pkt, d.mtu)
		if err != nil {
			break
		}
		p.staged = p.staged[1:]
		b, _ := m.MarshalBinary()
		d.send(p.endpoint, b)
		data = data || len(pkt) > 0
	}
	if len(p.staged) == 0 {
		p.staged = nil
	}
	d.anyAuthenticatedPacketTraversal(now, p)
	d.anyAuthenticatedPacketSent(p)
	if data {
		d.dataSent(now, p)
	}
	d.keepKeyFreshSending(now, p)
}

//go:build !mutant_norekey

package device

// Rekey and rejection decisions. They live in this file on their own so
// the mutant_norekey build of K3 can replace them (rekey_norekey.go).

// keypairExpired reports whether k is too old to send or receive with:
// REJECT_AFTER_TIME has passed since it was derived.
func keypairExpired(k *keypair, now int64) bool {
	return now-k.birth >= RejectAfterTime
}

// canSend reports whether k exists, has not expired and has not used
// REJECT_AFTER_MESSAGES counters.
func canSend(k *keypair, now int64) bool {
	return k != nil && !keypairExpired(k, now) && k.Sent() < RejectAfterMessages
}

// rekeyOnSend is the sending half of the kernel's keep_key_fresh: after
// REKEY_AFTER_MESSAGES messages, or REKEY_AFTER_TIME if this side was the
// initiator. It returns the reason, or "" for no rekey.
func rekeyOnSend(k *keypair, now int64) string {
	if k == nil {
		return ""
	}
	if k.Sent() > RekeyAfterMessages {
		return RekeySendMessages
	}
	if k.Initiator && now-k.birth >= RekeyAfterTime {
		return RekeySendAge
	}
	return ""
}

// rekeyOnReceive is the receiving half of keep_key_fresh: the initiator
// renews a key of REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
// (165 s) before the peer would have to stop sending.
func rekeyOnReceive(k *keypair, now int64) bool {
	return k != nil && k.Initiator && now-k.birth >= RekeyOnReceiveTime
}

func (d *Device) keepKeyFreshSending(now int64, p *peer) {
	if reason := rekeyOnSend(p.current, now); reason != "" {
		d.sendInitiation(now, p, false, reason)
	}
}

func (d *Device) keepKeyFreshReceiving(now int64, p *peer) {
	if !p.lastMinute && rekeyOnReceive(p.current, now) {
		p.lastMinute = true
		d.sendInitiation(now, p, false, RekeyReceiveAge)
	}
}

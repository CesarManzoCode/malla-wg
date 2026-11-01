//go:build mutant_norekey

package device

// Rekey and rejection decisions of the mutant mutant_norekey (contract
// §7, criterion 28): a keypair never expires by age and no rekey is ever
// started by its age or its message count, so TestCritRekeyTimers must
// catch it. Only the REJECT_AFTER_MESSAGES limit stays, because the
// nonce must not wrap.

func keypairExpired(k *keypair, now int64) bool { return false }

func canSend(k *keypair, now int64) bool {
	return k != nil && k.Sent() < RejectAfterMessages
}

func (d *Device) keepKeyFreshSending(now int64, p *peer) {}

func (d *Device) keepKeyFreshReceiving(now int64, p *peer) {}

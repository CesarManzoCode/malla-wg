//go:build mutant_nopunch

package magic

import "bytes"

// sendsPings of the mutant mutant_nopunch (contract §7, criterion 29):
// only the node whose WireGuard public key is the smaller one sends
// pings, in punching rounds, heartbeats and probes alike; the other only
// answers with pongs. Punching stops being simultaneous, and a node that
// never pings never confirms a direct address, so TestCritSimMatrix must
// find cells the theory gives as direct ending on relay.
func (b *Bind) sendsPings(p *peerState) bool {
	return bytes.Compare(b.nodeKey[:], p.key[:]) < 0
}

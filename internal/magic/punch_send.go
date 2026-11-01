//go:build !mutant_nopunch

package magic

// sendsPings reports whether the node pings p: always, so both sides of
// a punch send at once. The mutant mutant_nopunch replaces it
// (punch_nopunch.go).
func (b *Bind) sendsPings(p *peerState) bool { return true }

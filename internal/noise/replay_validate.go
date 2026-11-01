//go:build !mutant_noreplay

package noise

// ValidateCounter reports whether counter is accepted and, if so, marks it
// as seen. It rejects counters at or over limit, counters more than
// ReplayWindow behind the highest accepted one, and counters already seen.
func (f *ReplayFilter) ValidateCounter(counter, limit uint64) bool {
	if counter >= limit {
		return false
	}
	block := counter / replayBlockBits
	if counter > f.last {
		// Moving forward: clear the blocks between the old and the new
		// highest counter, at most the whole ring.
		current := f.last / replayBlockBits
		diff := min(block-current, replayRingBlocks)
		for i := current + 1; i <= current+diff; i++ {
			f.ring[i%replayRingBlocks] = 0
		}
		f.last = counter
	} else if f.last-counter > ReplayWindow {
		return false
	}
	slot := &f.ring[block%replayRingBlocks]
	bit := uint64(1) << (counter % replayBlockBits)
	if *slot&bit != 0 {
		return false
	}
	*slot |= bit
	return true
}

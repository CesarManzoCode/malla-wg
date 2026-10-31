package noise

// Anti-replay window of decision D07: a ring of 8192 bits in 64-bit blocks
// whose usable window is 8128 counters, the kernel's COUNTER_BITS_TOTAL
// minus one block and wireguard-go's (128 - 1) * 64.
const (
	replayBlockBits  = 64
	replayRingBlocks = 128
	// ReplayWindow is the largest distance behind the highest accepted
	// counter that is still accepted.
	ReplayWindow = (replayRingBlocks - 1) * replayBlockBits
)

// ReplayFilter is the receive-side sliding window of one keypair. The zero
// value is ready to use.
type ReplayFilter struct {
	last uint64
	ring [replayRingBlocks]uint64
}

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

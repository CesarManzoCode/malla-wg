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

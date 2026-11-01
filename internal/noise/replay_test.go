package noise

import (
	"math/rand/v2"
	"testing"
)

// modelWindow is the usable window of decision D07, written here
// independently of the package constant.
const modelWindow = 8128

// replayModel is the trivial reference: a set of every accepted counter
// and the highest one.
type replayModel struct {
	seen map[uint64]bool
	max  uint64
}

type rejectReason int

const (
	acceptedReason rejectReason = iota
	overLimit
	behindWindow
	alreadySeen
)

func (m *replayModel) validate(c, limit uint64) (bool, rejectReason) {
	if c >= limit {
		return false, overLimit
	}
	if c < m.max && m.max-c > modelWindow {
		return false, behindWindow
	}
	if m.seen[c] {
		return false, alreadySeen
	}
	m.seen[c] = true
	m.max = max(m.max, c)
	return true, acceptedReason
}

// nextCounter draws a new, repeated, reordered (inside the window), stale
// (before the window), boundary or over-limit counter.
func nextCounter(r *rand.Rand, m *replayModel, offered []uint64, limit uint64) uint64 {
	switch r.IntN(8) {
	case 0, 1: // new, close ahead
		return m.max + 1 + r.Uint64N(4)
	case 2: // new, with a jump of up to three rings
		return m.max + r.Uint64N(3*8192)
	case 3: // repeated
		if len(offered) > 0 {
			return offered[r.IntN(len(offered))]
		}
		return m.max
	case 4: // reordered inside the window
		return m.max - r.Uint64N(min(m.max, modelWindow)+1)
	case 5: // before the window
		if m.max > modelWindow {
			return m.max - modelWindow - 1 - r.Uint64N(min(m.max-modelWindow-1, 3*8192)+1)
		}
		return m.max + 1
	case 6: // window edges
		if m.max >= modelWindow+1 {
			return m.max - modelWindow - r.Uint64N(2)
		}
		return m.max
	default: // around the limit
		return limit - 2 + r.Uint64N(4)
	}
}

// TestCritAntiReplayProperty compares every decision of ReplayFilter with
// the reference model over seeded random sequences of new, repeated,
// reordered, stale, boundary and over-limit counters.
func TestCritAntiReplayProperty(t *testing.T) {
	const baseSeed = 20261031
	var reasons [4]int
	for seq := uint64(0); seq < 64; seq++ {
		seed := baseSeed + seq
		r := rand.New(rand.NewPCG(seed, 0))
		limit := RejectAfterMessages
		var m replayModel
		m.seen = map[uint64]bool{}
		switch seq % 4 {
		case 1: // a small limit, reached during the sequence
			limit = 20000 + r.Uint64N(40000)
		case 2: // start close to REJECT_AFTER_MESSAGES
			m.max = RejectAfterMessages - 40000
		}
		var f ReplayFilter
		if m.max != 0 {
			// Bring the filter to the same starting point as the model.
			if !f.ValidateCounter(m.max, limit) {
				t.Fatalf("property anti-replay violated: seed=%d step=start counter=%d limit=%d got=false want=true", seed, m.max, limit)
			}
			m.seen[m.max] = true
		}
		var offered []uint64
		for step := 0; step < 4000; step++ {
			c := nextCounter(r, &m, offered, limit)
			offered = append(offered, c)
			want, why := m.validate(c, limit)
			got := f.ValidateCounter(c, limit)
			if got != want {
				t.Fatalf("property anti-replay violated: seed=%d step=%d counter=%d limit=%d highest=%d got=%v want=%v",
					seed, step, c, limit, m.max, got, want)
			}
			reasons[why]++
		}
	}
	// The generator must reach every branch of the model; otherwise the
	// comparison proves less than it claims.
	names := [4]string{"accepted", "over limit", "behind window", "already seen"}
	for i, n := range reasons {
		if n == 0 {
			t.Errorf("property anti-replay violated: seed=%d generator never produced a %q decision", baseSeed, names[i])
		}
	}
}

func TestReplayFilterEdges(t *testing.T) {
	var f ReplayFilter
	if !f.ValidateCounter(0, RejectAfterMessages) || f.ValidateCounter(0, RejectAfterMessages) {
		t.Fatal("counter 0 must be accepted once")
	}
	if !f.ValidateCounter(ReplayWindow+100, RejectAfterMessages) {
		t.Fatal("jump forward rejected")
	}
	if !f.ValidateCounter(100, RejectAfterMessages) {
		t.Error("counter exactly ReplayWindow behind must be accepted")
	}
	if f.ValidateCounter(99, RejectAfterMessages) {
		t.Error("counter ReplayWindow+1 behind must be rejected")
	}
	if f.ValidateCounter(RejectAfterMessages, RejectAfterMessages) {
		t.Error("counter at the limit must be rejected")
	}
	if ReplayWindow != 8128 || replayRingBlocks*replayBlockBits != 8192 {
		t.Errorf("window %d over a %d-bit ring, want 8128 over 8192", ReplayWindow, replayRingBlocks*replayBlockBits)
	}
}

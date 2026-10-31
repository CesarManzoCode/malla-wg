// Package sim is the deterministic network simulator of the contract §5: a
// single-threaded event scheduler under a virtual clock in nanoseconds,
// hosts with addresses, links with latency, uniform jitter and Bernoulli
// loss, a middlebox hook on the path of every datagram and a JSON Lines
// event log. All randomness comes from one seed through math/rand/v2's
// ChaCha8, so the same seed produces the same log byte for byte.
package sim

import (
	"container/heap"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
)

// MaxEvents bounds the events of one RunUntil, so that a loop of events
// that never ends fails instead of hanging.
const MaxEvents = 50_000_000

// Ms is a millisecond in virtual nanoseconds.
const Ms int64 = 1e6

// Record is one line of the event log. The field order is the contract's
// §5: t, seq, ev, node, then the optional fields.
type Record struct {
	T      int64  `json:"t"`
	Seq    uint64 `json:"seq"`
	Ev     string `json:"ev"`
	Node   string `json:"node"`
	Src    string `json:"src,omitempty"`
	Dst    string `json:"dst,omitempty"`
	Len    int    `json:"len,omitempty"`
	Reason string `json:"reason,omitempty"`
	Peer   string `json:"peer,omitempty"`
}

type event struct {
	at  int64
	seq uint64
	fn  func()
}

type eventHeap []event

func (h eventHeap) Len() int { return len(h) }
func (h eventHeap) Less(i, j int) bool {
	if h[i].at != h[j].at {
		return h[i].at < h[j].at
	}
	return h[i].seq < h[j].seq
}
func (h eventHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *eventHeap) Push(x any)   { *h = append(*h, x.(event)) }
func (h *eventHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	*h = old[:len(old)-1]
	return e
}

// Sim is one simulation. It is not safe for concurrent use: everything
// runs in the goroutine that calls RunUntil.
type Sim struct {
	seed   uint64
	now    int64
	seq    uint64
	logSeq uint64
	queue  eventHeap
	root   *rand.ChaCha8
	log    io.Writer
	logErr error

	net network
}

// New returns a simulation at time 0 seeded with seed that writes its
// event log to log (nil discards it).
func New(seed uint64, log io.Writer) *Sim {
	var s [32]byte
	binary.LittleEndian.PutUint64(s[:], seed)
	if log == nil {
		log = io.Discard
	}
	sm := &Sim{seed: seed, root: rand.NewChaCha8(s), log: log}
	sm.net.init()
	return sm
}

// Seed returns the seed of the simulation.
func (s *Sim) Seed() uint64 { return s.seed }

// Now returns the virtual time in nanoseconds.
func (s *Sim) Now() int64 { return s.now }

// Stream returns a new random stream derived from the seed. Streams are
// handed out in call order, so a scenario that creates its hosts, links and
// other consumers in a fixed order gets the same streams every run.
func (s *Sim) Stream() *rand.ChaCha8 {
	var k [32]byte
	s.root.Read(k[:])
	return rand.NewChaCha8(k)
}

// At schedules fn at virtual time t, or now if t is in the past. Events at
// the same time run in the order they were scheduled.
func (s *Sim) At(t int64, fn func()) {
	s.seq++
	heap.Push(&s.queue, event{at: max(t, s.now), seq: s.seq, fn: fn})
}

// After schedules fn d nanoseconds from now.
func (s *Sim) After(d int64, fn func()) { s.At(s.now+d, fn) }

// RunUntil runs every event due at or before t and leaves the clock at t.
// It fails if the log could not be written or MaxEvents ran.
func (s *Sim) RunUntil(t int64) error {
	for n := 0; len(s.queue) > 0 && s.queue[0].at <= t; n++ {
		if n >= MaxEvents {
			return fmt.Errorf("sim: more than %d events before t=%d", MaxEvents, t)
		}
		e := heap.Pop(&s.queue).(event)
		s.now = e.at
		e.fn()
		if s.logErr != nil {
			return s.logErr
		}
	}
	s.now = max(s.now, t)
	return s.logErr
}

// Log writes r to the event log at the current time with the next
// sequence number.
func (s *Sim) Log(r Record) {
	s.logSeq++
	r.T, r.Seq = s.now, s.logSeq
	b, err := json.Marshal(r)
	if err == nil {
		_, err = s.log.Write(append(b, '\n'))
	}
	if err != nil && s.logErr == nil {
		s.logErr = fmt.Errorf("sim: event log: %w", err)
	}
}

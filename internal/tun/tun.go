// Package tun provides the TUN devices of a node: the Linux one, opened
// from /dev/net/tun, and an in-memory one for tests without privileges.
// Both carry bare IP packets, one per Read or Write.
package tun

import (
	"errors"
	"sync"
)

// Device is a TUN interface: Read returns one IP packet, Write sends one.
// Read blocks until a packet arrives or the device is closed, and then
// returns an error.
type Device interface {
	Name() string
	Read(b []byte) (int, error)
	Write(pkt []byte) (int, error)
	Close() error
}

// ErrClosed is returned by a closed in-memory device.
var ErrClosed = errors.New("tun: device closed")

// Mem is an in-memory TUN backed by channels. Packets injected with Inject
// are what the node reads; packets the node writes come out of Outbound.
// Like a kernel TUN whose queue is full, Write drops a packet when nobody
// drains Outbound and counts it in Dropped.
type Mem struct {
	name string
	in   chan []byte
	out  chan []byte

	closeOnce sync.Once
	closed    chan struct{}

	mu      sync.Mutex
	dropped int
}

// NewMem returns an in-memory TUN whose queues hold depth packets each.
func NewMem(name string, depth int) *Mem {
	return &Mem{
		name:   name,
		in:     make(chan []byte, depth),
		out:    make(chan []byte, depth),
		closed: make(chan struct{}),
	}
}

// Name returns the name given to NewMem.
func (m *Mem) Name() string { return m.name }

// Read returns the next injected packet, truncated to len(b).
func (m *Mem) Read(b []byte) (int, error) {
	select {
	case pkt := <-m.in:
		return copy(b, pkt), nil
	case <-m.closed:
		return 0, ErrClosed
	}
}

// Write queues a copy of pkt on Outbound, or drops it if the queue is full.
func (m *Mem) Write(pkt []byte) (int, error) {
	select {
	case <-m.closed:
		return 0, ErrClosed
	default:
	}
	select {
	case m.out <- append([]byte(nil), pkt...):
	default:
		m.mu.Lock()
		m.dropped++
		m.mu.Unlock()
	}
	return len(pkt), nil
}

// Close makes Read and Write fail with ErrClosed.
func (m *Mem) Close() error {
	m.closeOnce.Do(func() { close(m.closed) })
	return nil
}

// Inject queues a copy of pkt for the node to read, blocking while the
// queue is full; it returns ErrClosed if the device is closed.
func (m *Mem) Inject(pkt []byte) error {
	select {
	case m.in <- append([]byte(nil), pkt...):
		return nil
	case <-m.closed:
		return ErrClosed
	}
}

// Outbound returns the packets the node wrote, in order.
func (m *Mem) Outbound() <-chan []byte { return m.out }

// Dropped returns how many written packets did not fit in Outbound.
func (m *Mem) Dropped() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dropped
}

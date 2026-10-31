//go:build linux

package tun

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Linux is a kernel TUN interface opened with IFF_TUN|IFF_NO_PI, so every
// Read and Write is one bare IP packet without the 4-byte packet header.
//
// The interface is created in the network namespace of the calling thread:
// a node that must live in a namespace opens its TUN from a thread that
// already joined it (see verify/netns.Do).
type Linux struct {
	f    *os.File
	name string
}

// OpenLinux creates or attaches to the TUN interface name; an empty name
// lets the kernel pick one (tun0, tun1, …). The interface starts down and
// without addresses: the caller configures it.
func OpenLinux(name string) (*Linux, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: open /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: %w", err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: TUNSETIFF %q: %w", name, err)
	}
	// A non-blocking descriptor goes to Go's poller, so Close unblocks a
	// pending Read instead of leaving it stuck in the kernel.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: set non-blocking: %w", err)
	}
	return &Linux{f: os.NewFile(uintptr(fd), "/dev/net/tun"), name: ifr.Name()}, nil
}

// Name returns the interface name the kernel assigned.
func (l *Linux) Name() string { return l.name }

// Read reads one IP packet.
func (l *Linux) Read(b []byte) (int, error) { return l.f.Read(b) }

// Write writes one IP packet.
func (l *Linux) Write(pkt []byte) (int, error) { return l.f.Write(pkt) }

// Close closes the descriptor; the kernel removes a non-persistent
// interface with it.
func (l *Linux) Close() error { return l.f.Close() }

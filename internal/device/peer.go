package device

import (
	"net/netip"

	"github.com/CesarManzoCode/malla-wg/internal/noise"
)

// keypair is a transport keypair with the time it was derived.
type keypair struct {
	*noise.Keypair
	birth int64
}

// timer is a deadline that is either armed or not.
type timer struct {
	at int64
	on bool
}

func (t *timer) arm(at int64) { *t = timer{at: at, on: true} }
func (t *timer) stop()        { t.on = false }

// due disarms the timer and reports true if it is armed and expired.
func (t *timer) due(now int64) bool {
	if !t.on || t.at > now {
		return false
	}
	t.on = false
	return true
}

// peer is the device's state for one remote static key.
type peer struct {
	key        [noise.KeySize]byte
	noise      *noise.Peer
	endpoint   netip.AddrPort
	persistent int64

	// Keypairs as in the kernel's noise.c: the responder keeps a new
	// keypair in next until the first data message arrives with it.
	current, previous, next *keypair

	hsIndex   uint32 // local index of the initiation in flight
	hsPending bool

	staged [][]byte

	lastHandshake int64 // now of the last initiation or response sent
	sentHandshake bool
	attemptStart  int64 // now of the first initiation of the attempt
	lastMinute    bool  // the receive-side rekey was sent for current

	needAnotherKeepalive bool

	// The kernel's five per-peer timers.
	retransmit   timer // retransmit the initiation
	keepalive    timer // answer received data
	newHandshake timer // data sent and nothing received
	zeroKeys     timer // erase key material
	persistentKA timer // persistent keepalive
}

func (p *peer) nextDeadline() int64 {
	next := Never
	for _, t := range [...]*timer{&p.retransmit, &p.keepalive, &p.newHandshake, &p.zeroKeys, &p.persistentKA} {
		if t.on {
			next = min(next, t.at)
		}
	}
	return next
}

// retire removes a keypair from the index table.
func (d *Device) retire(k *keypair) {
	if k != nil {
		delete(d.indices, k.LocalIndex)
	}
}

// dropHandshakeIndex forgets the index of the initiation in flight, whose
// handshake state was overwritten or erased.
func (d *Device) dropHandshakeIndex(p *peer) {
	if p.hsPending {
		if e, ok := d.indices[p.hsIndex]; ok && e.kp == nil {
			delete(d.indices, p.hsIndex)
		}
		p.hsPending = false
	}
}

// addKeypair installs a new keypair as the kernel's add_new_keypair: the
// initiator uses it at once, the responder keeps it in next.
func (d *Device) addKeypair(p *peer, k *keypair) {
	if k.Initiator {
		if p.next != nil {
			d.retire(p.previous)
			d.retire(p.current)
			p.previous, p.next = p.next, nil
		} else {
			d.retire(p.previous)
			p.previous = p.current
		}
		p.current = k
		p.lastMinute = false
		return
	}
	d.retire(p.next)
	d.retire(p.previous)
	p.next, p.previous = k, nil
}

// receivedWithKeypair promotes next to current when the first data
// message arrives with it, and reports whether it did.
func (d *Device) receivedWithKeypair(p *peer, k *keypair) bool {
	if p.next != k {
		return false
	}
	d.retire(p.previous)
	p.previous, p.current, p.next = p.current, k, nil
	p.lastMinute = false
	return true
}

// clearKeys erases every keypair and the handshake in flight.
func (d *Device) clearKeys(p *peer) {
	d.retire(p.current)
	d.retire(p.previous)
	d.retire(p.next)
	p.current, p.previous, p.next = nil, nil, nil
	d.dropHandshakeIndex(p)
}

func (d *Device) setEndpoint(p *peer, src netip.AddrPort) {
	if p.endpoint == src {
		return
	}
	p.endpoint = src
	d.out.Events = append(d.out.Events, Event{Kind: EventEndpoint, Peer: p.key, Endpoint: src})
}

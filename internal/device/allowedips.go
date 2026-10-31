package device

import (
	"encoding/binary"
	"net/netip"
)

// allowedIPs maps addresses to peers by longest prefix match, with one
// binary trie per address family. Inserting a prefix that is already
// present moves it to the new peer, as in the kernel.
type allowedIPs struct {
	v4, v6 *trieNode
}

type trieNode struct {
	child [2]*trieNode
	peer  *peer
}

func bitAt(b []byte, i int) int {
	return int(b[i/8]>>(7-i%8)) & 1
}

func (t *allowedIPs) root(a netip.Addr, create bool) *trieNode {
	r := &t.v6
	if a.Is4() {
		r = &t.v4
	}
	if *r == nil && create {
		*r = &trieNode{}
	}
	return *r
}

func (t *allowedIPs) insert(pfx netip.Prefix, p *peer) {
	pfx = pfx.Masked()
	n := t.root(pfx.Addr(), true)
	bits := pfx.Addr().AsSlice()
	for i := range pfx.Bits() {
		b := bitAt(bits, i)
		if n.child[b] == nil {
			n.child[b] = &trieNode{}
		}
		n = n.child[b]
	}
	n.peer = p
}

// remove deletes every prefix that points to p.
func (t *allowedIPs) remove(p *peer) {
	var walk func(n *trieNode)
	walk = func(n *trieNode) {
		if n == nil {
			return
		}
		if n.peer == p {
			n.peer = nil
		}
		walk(n.child[0])
		walk(n.child[1])
	}
	walk(t.v4)
	walk(t.v6)
}

// lookup returns the peer of the longest prefix holding a, or nil.
func (t *allowedIPs) lookup(a netip.Addr) *peer {
	if !a.IsValid() {
		return nil
	}
	n := t.root(a, false)
	bits := a.AsSlice()
	var best *peer
	for i := 0; n != nil; i++ {
		if n.peer != nil {
			best = n.peer
		}
		if i == len(bits)*8 {
			break
		}
		n = n.child[bitAt(bits, i)]
	}
	return best
}

// parseIP reads the version and length of an IPv4 or IPv6 header, and
// returns the packet trimmed to that length (dropping transport padding)
// with its source and destination.
func parseIP(b []byte) (pkt []byte, src, dst netip.Addr, ok bool) {
	if len(b) == 0 {
		return nil, src, dst, false
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return nil, src, dst, false
		}
		n := int(binary.BigEndian.Uint16(b[2:4]))
		if n < 20 || n > len(b) {
			return nil, src, dst, false
		}
		return b[:n], netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20])), true
	case 6:
		if len(b) < 40 {
			return nil, src, dst, false
		}
		n := 40 + int(binary.BigEndian.Uint16(b[4:6]))
		if n > len(b) {
			return nil, src, dst, false
		}
		return b[:n], netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40])), true
	}
	return nil, src, dst, false
}

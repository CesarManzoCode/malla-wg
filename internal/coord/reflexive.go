package coord

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
)

// ReflexiveMagic starts every message of the reflexive endpoint service.
// WireGuard messages start with a type of 1 to 4 and three zeros, so the
// two never share a prefix on the node's socket.
const ReflexiveMagic = "mallaSTN"

// DefaultReflexivePort is the service's UDP port when nothing else is set.
const DefaultReflexivePort = 3478

const (
	reflexiveRequestLen = len(ReflexiveMagic) + 12
	reflexiveReplyLen   = reflexiveRequestLen + 18
)

// IsReflexive reports whether b is a message of the reflexive service.
func IsReflexive(b []byte) bool { return bytes.HasPrefix(b, []byte(ReflexiveMagic)) }

// ReflexiveRequest is "mallaSTN" + txid.
func ReflexiveRequest(txid [12]byte) []byte {
	return append([]byte(ReflexiveMagic), txid[:]...)
}

// ReflexiveReply answers a request from src: "mallaSTN" + txid + src as a
// 16-byte IPv4-mapped address and a big-endian port. It is false if req
// is not a request.
func ReflexiveReply(req []byte, src netip.AddrPort) ([]byte, bool) {
	if len(req) != reflexiveRequestLen || !IsReflexive(req) || !src.IsValid() {
		return nil, false
	}
	b := make([]byte, 0, reflexiveReplyLen)
	b = append(b, req...)
	a := src.Addr().As16() // As16 maps IPv4
	b = append(b, a[:]...)
	return binary.BigEndian.AppendUint16(b, src.Port()), true
}

// ParseReflexiveReply decodes a reply; an IPv4-mapped address comes back
// as plain IPv4.
func ParseReflexiveReply(b []byte) (txid [12]byte, addr netip.AddrPort, ok bool) {
	if len(b) != reflexiveReplyLen || !IsReflexive(b) {
		return txid, addr, false
	}
	copy(txid[:], b[len(ReflexiveMagic):])
	ip := netip.AddrFrom16([16]byte(b[reflexiveRequestLen : reflexiveRequestLen+16])).Unmap()
	port := binary.BigEndian.Uint16(b[reflexiveRequestLen+16:])
	return txid, netip.AddrPortFrom(ip, port), true
}

// ServeReflexive answers requests on conn until conn is closed, and then
// returns the read error.
func ServeReflexive(conn *net.UDPConn) error {
	buf := make([]byte, 64)
	for {
		n, src, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return err
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		if resp, ok := ReflexiveReply(buf[:n], src); ok {
			conn.WriteToUDPAddrPort(resp, src)
		}
	}
}

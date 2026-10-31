package magic

import (
	"net/netip"
	"slices"
)

// MaxEndpoints bounds the endpoints a node reports, as the coordination
// does.
const MaxEndpoints = 16

// Endpoints is the node's endpoint discovery: the reflexive address the
// coordination's service observed, first, then the local addresses with
// the listening port, without repeats, invalid, unspecified or excluded
// addresses (the mesh's own), and at most MaxEndpoints. Which local
// addresses count (a socket bound to loopback, say) is the caller's call.
func Endpoints(reflexive netip.AddrPort, local []netip.Addr, port uint16, exclude netip.Prefix) []netip.AddrPort {
	var eps []netip.AddrPort
	add := func(ap netip.AddrPort) {
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		a := ap.Addr()
		if !ap.IsValid() || ap.Port() == 0 || a.IsUnspecified() ||
			(exclude.IsValid() && exclude.Contains(a)) || slices.Contains(eps, ap) || len(eps) == MaxEndpoints {
			return
		}
		eps = append(eps, ap)
	}
	add(reflexive)
	for _, a := range local {
		add(netip.AddrPortFrom(a, port))
	}
	return eps
}

// EndpointsChanged reports whether the endpoints to report differ from
// the last reported ones, so the node reports to /v1/endpoints only when
// they change.
func EndpointsChanged(reported, now []netip.AddrPort) bool {
	return !slices.Equal(reported, now)
}

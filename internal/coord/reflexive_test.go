package coord

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestReflexiveObservedAddress runs the reflexive service on 127.0.0.1
// and checks that it answers a request with the request's txid and the
// address and port the request came from.
func TestReflexiveObservedAddress(t *testing.T) {
	loopback := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	srv, err := net.ListenUDP("udp4", loopback)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- ServeReflexive(srv) }()
	defer func() { srv.Close(); <-done }()

	cl, err := net.ListenUDP("udp4", loopback)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	srvAddr := srv.LocalAddr().(*net.UDPAddr).AddrPort()
	want := cl.LocalAddr().(*net.UDPAddr).AddrPort()
	want = netip.AddrPortFrom(want.Addr().Unmap(), want.Port())

	// A malformed request gets no answer; the valid one after it does.
	if _, err := cl.WriteToUDPAddrPort([]byte("mallaSTN-short"), srvAddr); err != nil {
		t.Fatal(err)
	}
	txid := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	if _, err := cl.WriteToUDPAddrPort(ReflexiveRequest(txid), srvAddr); err != nil {
		t.Fatal(err)
	}
	if err := cl.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, from, err := cl.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	if netip.AddrPortFrom(from.Addr().Unmap(), from.Port()) != srvAddr {
		t.Fatalf("reply from %s, want %s", from, srvAddr)
	}
	got, addr, ok := ParseReflexiveReply(buf[:n])
	if !ok {
		t.Fatalf("reply %x does not parse", buf[:n])
	}
	if got != txid {
		t.Fatalf("txid %x, want %x", got, txid)
	}
	if addr != want {
		t.Fatalf("observed address %s, want %s", addr, want)
	}
}

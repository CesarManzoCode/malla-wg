package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// wgTransport returns a minimal WireGuard transport message: type 4,
// three zeros, receiver index, counter and a 16-byte tag, with fill
// after the header.
func wgTransport(fill byte, n int) []byte {
	b := make([]byte, 32+n)
	b[0] = 4
	for i := 16; i < len(b); i++ {
		b[i] = fill
	}
	return b
}

func key(b byte) [KeyLen]byte {
	var k [KeyLen]byte
	for i := range k {
		k[i] = b
	}
	return k
}

func TestFrameRoundTrip(t *testing.T) {
	k := key(7)
	dg := wgTransport(0xaa, 100)
	cases := []struct {
		t     Type
		parts [][]byte
	}{
		{TypeClientHello, [][]byte{k[:]}},
		{TypeServerHello, nil},
		{TypeSendPacket, [][]byte{k[:], dg}},
		{TypeRecvPacket, [][]byte{k[:], dg}},
		{TypeKeepAlive, nil},
		{TypePeerGone, [][]byte{k[:]}},
	}
	var stream []byte
	for _, c := range cases {
		f := AppendFrame(nil, c.t, c.parts...)
		want := bytes.Join(c.parts, nil)
		if len(f) != HeaderLen+len(want) || Type(f[0]) != c.t || binary.BigEndian.Uint32(f[1:5]) != uint32(len(want)) {
			t.Fatalf("%s: header % x", c.t, f[:HeaderLen])
		}
		// Every strict prefix is incomplete, not an error.
		for i := range len(f) {
			if _, _, n, err := ParseFrame(f[:i]); n != 0 || err != nil {
				t.Fatalf("%s: prefix of %d bytes: n=%d err=%v", c.t, i, n, err)
			}
		}
		typ, payload, n, err := ParseFrame(append(bytes.Clone(f), 0xff))
		if err != nil || n != len(f) || typ != c.t || !bytes.Equal(payload, want) {
			t.Fatalf("%s: ParseFrame = %s % x %d %v", c.t, typ, payload, n, err)
		}
		stream = append(stream, f...)
	}
	r := bytes.NewReader(stream)
	var buf []byte
	for _, c := range cases {
		var typ Type
		var payload []byte
		var err error
		typ, payload, buf, err = ReadFrame(r, buf)
		if err != nil || typ != c.t || !bytes.Equal(payload, bytes.Join(c.parts, nil)) {
			t.Fatalf("ReadFrame: %s % x %v, want %s", typ, payload, err, c.t)
		}
	}
	if _, _, _, err := ReadFrame(r, buf); !errors.Is(err, io.EOF) {
		t.Fatalf("ReadFrame at the end: %v, want EOF", err)
	}

	big := []byte{byte(TypeSendPacket), 0, 0, 0, 0}
	binary.BigEndian.PutUint32(big[1:], MaxPayload+1)
	if _, _, _, err := ParseFrame(big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized ParseFrame: %v", err)
	}
	if _, _, _, err := ReadFrame(bytes.NewReader(big), nil); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized ReadFrame: %v", err)
	}
	if _, _, _, err := ReadFrame(bytes.NewReader(AppendFrame(nil, TypeSendPacket, k[:])[:10]), nil); err == nil {
		t.Fatal("truncated frame read without error")
	}
	if _, _, err := SplitPacket(k[:31]); !errors.Is(err, ErrMalformed) {
		t.Fatalf("short packet payload: %v", err)
	}
	if _, err := ParseKey(append(k[:], 0)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("long key payload: %v", err)
	}
}

func TestForwardable(t *testing.T) {
	ini := make([]byte, 148)
	ini[0] = 1
	for _, c := range []struct {
		b    []byte
		want bool
	}{
		{ini, true},
		{wgTransport(0, 0), true},
		{append([]byte("mallaDSC"), make([]byte, 60)...), true},
		{[]byte("GET / HTTP/1.1\r\n"), false},
		{append([]byte{4, 1, 0, 0}, make([]byte, 40)...), false},
		{ini[:100], false},
		{nil, false},
	} {
		if got := Forwardable(c.b); got != c.want {
			t.Errorf("Forwardable(% x…) = %v, want %v", c.b[:min(8, len(c.b))], got, c.want)
		}
	}
}

func TestCoreForwarding(t *testing.T) {
	c := NewCore()
	ka, kb := key(1), key(2)
	if _, err := c.Handle(1, TypeSendPacket, append(kb[:], wgTransport(0, 0)...)); !errors.Is(err, ErrNoHello) {
		t.Fatalf("send before hello: %v", err)
	}
	for id, k := range map[ConnID][KeyLen]byte{1: ka, 2: kb} {
		r, err := c.Handle(id, TypeClientHello, k[:])
		if err != nil || len(r.Out) != 1 || r.Out[0].To != id || Type(r.Out[0].Frame[0]) != TypeServerHello {
			t.Fatalf("hello of %d: %+v %v", id, r, err)
		}
	}
	if _, err := c.Handle(1, TypeClientHello, ka[:]); !errors.Is(err, ErrSecondHello) {
		t.Fatalf("second hello: %v", err)
	}

	dg := wgTransport(0x55, 64)
	r, err := c.Handle(1, TypeSendPacket, append(kb[:], dg...))
	if err != nil || len(r.Out) != 1 || r.Out[0].To != 2 || !bytes.Equal(r.Forwarded, dg) {
		t.Fatalf("a to b: %+v %v", r, err)
	}
	typ, payload, _, _ := ParseFrame(r.Out[0].Frame)
	src, got, _ := SplitPacket(payload)
	if typ != TypeRecvPacket || src != ka || !bytes.Equal(got, dg) {
		t.Fatalf("b got %s from %x: % x", typ, src[:4], got)
	}

	// Unknown destination: PeerGone back to the sender.
	kc := key(3)
	r, err = c.Handle(1, TypeSendPacket, append(kc[:], dg...))
	if err != nil || len(r.Out) != 1 || r.Out[0].To != 1 || r.Forwarded != nil {
		t.Fatalf("a to unknown c: %+v %v", r, err)
	}
	if typ, payload, _, _ := ParseFrame(r.Out[0].Frame); typ != TypePeerGone || !bytes.Equal(payload, kc[:]) {
		t.Fatalf("a to unknown c: got %s % x", typ, payload)
	}

	// Plain text is not forwarded.
	r, err = c.Handle(1, TypeSendPacket, append(kb[:], []byte("secret in clear")...))
	if err != nil || len(r.Out) != 0 || r.Forwarded != nil || c.Dropped != 2 {
		t.Fatalf("plain text: %+v %v dropped=%d", r, err, c.Dropped)
	}

	// A newer connection for b replaces the old one, which is closed;
	// the old one closing later does not unregister b.
	r, err = c.Handle(3, TypeClientHello, kb[:])
	if err != nil || len(r.Close) != 1 || r.Close[0] != 2 {
		t.Fatalf("second connection of b: %+v %v", r, err)
	}
	c.Closed(2)
	if r, _ := c.Handle(1, TypeSendPacket, append(kb[:], dg...)); len(r.Out) != 1 || r.Out[0].To != 3 {
		t.Fatalf("a to b after b reconnected: %+v", r)
	}
	c.Closed(3)
	if r, _ := c.Handle(1, TypeSendPacket, append(kb[:], dg...)); r.Forwarded != nil {
		t.Fatalf("a to b after b left: %+v", r)
	}
	if _, err := c.Handle(1, TypeRecvPacket, append(kb[:], dg...)); !errors.Is(err, ErrUnexpected) {
		t.Fatalf("RecvPacket from a client: %v", err)
	}
	if c.Conns() != 1 {
		t.Fatalf("Conns = %d, want 1", c.Conns())
	}
}

type received struct {
	src [KeyLen]byte
	dg  []byte
}

func startClient(t *testing.T, url, fp string, k [KeyLen]byte) (*Client, chan received) {
	t.Helper()
	got := make(chan received, 16)
	c, err := NewClient(ClientConfig{
		URL: url, Fingerprint: fp, NodeKey: k,
		OnPacket: func(src [KeyLen]byte, dg []byte) { got <- received{src, bytes.Clone(dg)} },
		Logf:     t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return c, got
}

// TestServerClientLoopback forwards datagrams between two clients through
// a server on 127.0.0.1, checks that a client with the wrong pin never
// connects, and reads the capture file.
func TestServerClientLoopback(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "capture.bin")
	var logMu sync.Mutex
	srv, err := NewServer(ServerConfig{StateDir: dir, CaptureFile: capture, Logf: func(f string, a ...any) {
		logMu.Lock()
		defer logMu.Unlock()
		t.Logf(f, a...)
	}})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { srv.Serve(ctx, ln); close(served) }()
	url := "https://" + ln.Addr().String()

	ka, kb := key(0xa), key(0xb)
	a, gotA := startClient(t, url, srv.Fingerprint(), ka)
	b, gotB := startClient(t, url, srv.Fingerprint(), kb)
	wrongFP := strings.Repeat("00", 32)
	bad, _ := startClient(t, url, wrongFP, key(0xc))
	for end := time.Now().Add(10 * time.Second); !(a.Connected() && b.Connected()); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("clients did not connect in 10 s")
		}
	}

	var sent [][]byte
	exchange := func(from *Client, to [KeyLen]byte, got chan received, fromKey [KeyLen]byte, fill byte) {
		t.Helper()
		dg := wgTransport(fill, 200)
		if !from.Send(to, dg) {
			t.Fatal("Send failed")
		}
		sent = append(sent, dg)
		select {
		case r := <-got:
			if r.src != fromKey || !bytes.Equal(r.dg, dg) {
				t.Fatalf("received % x… from %x, want the datagram from %x", r.dg[:8], r.src[:4], fromKey[:4])
			}
		case <-time.After(5 * time.Second):
			t.Fatal("datagram not relayed in 5 s")
		}
	}
	exchange(a, kb, gotB, ka, 1)
	exchange(b, ka, gotA, kb, 2)
	exchange(a, kb, gotB, ka, 3)
	if bad.Connected() {
		t.Fatal("client with the wrong fingerprint connected")
	}
	if a.Send(kb, []byte("plain text")) {
		// Queued, but the server must not forward it.
		select {
		case r := <-gotB:
			t.Fatalf("plain text forwarded: %q", r.dg)
		case <-time.After(300 * time.Millisecond):
		}
	}

	cancel()
	<-served
	raw, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	var recs [][]byte
	for len(raw) > 0 {
		if len(raw) < 4 {
			t.Fatalf("capture ends with %d stray bytes", len(raw))
		}
		n := binary.BigEndian.Uint32(raw)
		if uint32(len(raw)-4) < n {
			t.Fatalf("capture record of %d bytes truncated", n)
		}
		recs = append(recs, raw[4:4+n])
		raw = raw[4+n:]
	}
	if len(recs) != len(sent) {
		t.Fatalf("capture has %d records, want %d", len(recs), len(sent))
	}
	for i := range recs {
		if !bytes.Equal(recs[i], sent[i]) {
			t.Fatalf("capture record %d differs", i)
		}
	}
}

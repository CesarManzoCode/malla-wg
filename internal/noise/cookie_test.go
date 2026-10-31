package noise

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

func TestCookieFlow(t *testing.T) {
	tp := newTestPair(t, 7, [KeySize]byte{}, [KeySize]byte{})
	src := netip.MustParseAddrPort("192.0.2.1:51820")

	// First initiation: no cookie yet, so mac2 is zero and fails under load.
	b := tp.initiation(t, testNow, testWall)
	if !bytes.Equal(b[132:], make([]byte, 16)) {
		t.Fatalf("mac2 without a cookie = %x, want zeros", b[132:])
	}
	if !tp.lr.CheckMAC1(b) {
		t.Fatal("valid mac1 rejected")
	}
	if ok, err := tp.lr.CheckMAC2(b, src, testNow, tp.rnd); err != nil || ok {
		t.Fatalf("zero mac2 accepted: %v %v", ok, err)
	}

	// The responder, under load, answers with a cookie reply.
	reply, err := tp.lr.CreateCookieReply(b, src, testNow, tp.rnd)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Receiver != tp.initIdx {
		t.Errorf("cookie reply receiver %#x, want the initiation sender %#x", reply.Receiver, tp.initIdx)
	}
	rb, _ := reply.MarshalBinary()
	if len(rb) != CookieReplySize {
		t.Fatalf("cookie reply is %d bytes", len(rb))
	}
	var got CookieReply
	if err := got.UnmarshalBinary(rb); err != nil {
		t.Fatal(err)
	}

	// A tampered reply fails and leaves the pending mac1 usable.
	bad := got
	bad.Cookie[0] ^= 1
	if err := tp.toResp.ConsumeCookieReply(&bad, testNow); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered cookie reply: %v, want ErrDecrypt", err)
	}
	if err := tp.toResp.ConsumeCookieReply(&got, testNow); err != nil {
		t.Fatalf("ConsumeCookieReply: %v", err)
	}
	if err := tp.toResp.ConsumeCookieReply(&got, testNow); !errors.Is(err, ErrNoMAC1Sent) {
		t.Fatalf("second cookie reply for the same mac1: %v, want ErrNoMAC1Sent", err)
	}

	// The retransmitted initiation carries a valid mac2 for src only.
	now2 := testNow + 100e6
	b2 := tp.initiation(t, now2, testWall+1e9)
	if bytes.Equal(b2[132:], make([]byte, 16)) {
		t.Fatal("mac2 still zero after consuming a cookie")
	}
	if !tp.lr.CheckMAC1(b2) {
		t.Fatal("mac1 of the retransmission rejected")
	}
	if ok, err := tp.lr.CheckMAC2(b2, src, now2, tp.rnd); err != nil || !ok {
		t.Fatalf("valid mac2 rejected: %v %v", ok, err)
	}
	for _, other := range []string{"192.0.2.1:51821", "192.0.2.2:51820", "[2001:db8::1]:51820"} {
		if ok, _ := tp.lr.CheckMAC2(b2, netip.MustParseAddrPort(other), now2, tp.rnd); ok {
			t.Errorf("mac2 accepted from %s", other)
		}
	}
	if ok, _ := tp.lr.CheckMAC2(b2, netip.MustParseAddrPort("[::ffff:192.0.2.1]:51820"), now2, tp.rnd); !ok {
		t.Error("IPv4-mapped form of the same source rejected")
	}
	if err := tp.consumeInitiation(b2, now2); err != nil {
		t.Fatalf("initiation with cookie: %v", err)
	}

	// The responder's response gets a cookie reply in the other direction.
	resp, err := tp.toInit.CreateResponse(tp.rnd, now2, tp.respIdx)
	if err != nil {
		t.Fatal(err)
	}
	respWire, _ := resp.MarshalBinary()
	initSrc := netip.MustParseAddrPort("198.51.100.7:4000")
	back, err := tp.li.CreateCookieReply(respWire, initSrc, now2, tp.rnd)
	if err != nil {
		t.Fatal(err)
	}
	if back.Receiver != tp.respIdx {
		t.Errorf("cookie reply to a response has receiver %#x, want %#x", back.Receiver, tp.respIdx)
	}
	if err := tp.toInit.ConsumeCookieReply(back, now2); err != nil {
		t.Fatalf("responder could not consume the cookie reply: %v", err)
	}

	// After 115 s the initiator stops using the cookie.
	b3 := tp.initiation(t, testNow+115e9, testWall+2e9)
	if !bytes.Equal(b3[132:], make([]byte, 16)) {
		t.Error("mac2 still set with a cookie 115 s old")
	}
	// After 120 s the responder's secret rotates and the old mac2 fails.
	if ok, _ := tp.lr.CheckMAC2(b2, src, testNow+120e9, tp.rnd); ok {
		t.Error("mac2 accepted after the cookie secret rotated")
	}
}

func TestInvalidMAC1Rejected(t *testing.T) {
	tp := newTestPair(t, 8, [KeySize]byte{}, [KeySize]byte{})
	b := tp.initiation(t, testNow, testWall)
	if !tp.lr.CheckMAC1(b) {
		t.Fatal("valid mac1 rejected")
	}
	flipped := bytes.Clone(b)
	flipped[116] ^= 1
	if tp.lr.CheckMAC1(flipped) {
		t.Error("initiation with a flipped mac1 accepted")
	}
	body := bytes.Clone(b)
	body[20] ^= 1
	if tp.lr.CheckMAC1(body) {
		t.Error("initiation with a modified body accepted")
	}
	if tp.li.CheckMAC1(b) {
		t.Error("mac1 accepted by a node it was not addressed to")
	}
	if tp.lr.CheckMAC1(b[:147]) || tp.lr.CheckMAC1(nil) {
		t.Error("CheckMAC1 accepted a truncated message")
	}
	if _, err := tp.lr.CreateCookieReply(b[:147], netip.MustParseAddrPort("192.0.2.1:1"), testNow, tp.rnd); err == nil {
		t.Error("cookie reply created for a truncated message")
	}

	if err := tp.consumeInitiation(b, testNow); err != nil {
		t.Fatal(err)
	}
	resp, err := tp.toInit.CreateResponse(tp.rnd, testNow, tp.respIdx)
	if err != nil {
		t.Fatal(err)
	}
	rb, _ := resp.MarshalBinary()
	if !tp.li.CheckMAC1(rb) {
		t.Fatal("valid response mac1 rejected")
	}
	rb[60] ^= 1
	if tp.li.CheckMAC1(rb) {
		t.Error("response with a flipped mac1 accepted")
	}
}

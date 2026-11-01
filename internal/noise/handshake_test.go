package noise

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"testing"
)

// Times used by the tests: a monotonic now and a Unix wall clock. Wall
// steps are at least 1 s so TAI64N labels differ after whitening.
const (
	testNow  int64 = 1_000_000_000
	testWall int64 = 1_793_000_000 * 1e9
)

type testPair struct {
	rnd              *rand.ChaCha8
	li, lr           *Local
	toResp, toInit   *Peer // the initiator's view of the responder, and the reverse
	lookupInitiator  func([KeySize]byte) *Peer
	initIdx, respIdx uint32
}

func newTestPair(t *testing.T, seed byte, pskI, pskR [KeySize]byte) *testPair {
	t.Helper()
	tp := &testPair{rnd: rand.NewChaCha8([32]byte{seed}), initIdx: 0x11111111, respIdx: 0x22222222}
	privI, err := GeneratePrivateKey(tp.rnd)
	if err != nil {
		t.Fatal(err)
	}
	privR, err := GeneratePrivateKey(tp.rnd)
	if err != nil {
		t.Fatal(err)
	}
	tp.li, tp.lr = NewLocal(privI), NewLocal(privR)
	if tp.toResp, err = tp.li.NewPeer(tp.lr.PublicKey(), pskI); err != nil {
		t.Fatal(err)
	}
	if tp.toInit, err = tp.lr.NewPeer(tp.li.PublicKey(), pskR); err != nil {
		t.Fatal(err)
	}
	tp.lookupInitiator = func(k [KeySize]byte) *Peer {
		if k == tp.li.PublicKey() {
			return tp.toInit
		}
		return nil
	}
	return tp
}

// initiation creates an initiation and returns its wire form.
func (tp *testPair) initiation(t *testing.T, now, wall int64) []byte {
	t.Helper()
	m, err := tp.toResp.CreateInitiation(tp.rnd, now, wall, tp.initIdx)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := m.MarshalBinary()
	if len(b) != InitiationSize {
		t.Fatalf("initiation is %d bytes", len(b))
	}
	return b
}

func (tp *testPair) consumeInitiation(b []byte, now int64) error {
	var m Initiation
	if err := m.UnmarshalBinary(b); err != nil {
		return err
	}
	p, err := tp.lr.ConsumeInitiation(&m, now, tp.lookupInitiator)
	if err == nil && p != tp.toInit {
		return errors.New("ConsumeInitiation returned the wrong peer")
	}
	return err
}

// run performs a whole handshake over the wire forms and returns the
// initiator's and the responder's keypairs.
func (tp *testPair) run(t *testing.T, now, wall int64) (kpI, kpR *Keypair, err error) {
	t.Helper()
	b := tp.initiation(t, now, wall)
	if !tp.lr.CheckMAC1(b) {
		t.Fatal("responder rejected the initiator's mac1")
	}
	if err := tp.consumeInitiation(b, now); err != nil {
		t.Fatalf("ConsumeInitiation: %v", err)
	}
	resp, err := tp.toInit.CreateResponse(tp.rnd, now, tp.respIdx)
	if err != nil {
		t.Fatalf("CreateResponse: %v", err)
	}
	rb, _ := resp.MarshalBinary()
	if len(rb) != ResponseSize {
		t.Fatalf("response is %d bytes", len(rb))
	}
	if !tp.li.CheckMAC1(rb) {
		t.Fatal("initiator rejected the responder's mac1")
	}
	var got Response
	if err := got.UnmarshalBinary(rb); err != nil {
		t.Fatal(err)
	}
	if got.Receiver != tp.initIdx || got.Sender != tp.respIdx {
		t.Fatalf("response indices sender=%#x receiver=%#x", got.Sender, got.Receiver)
	}
	if err := tp.toResp.ConsumeResponse(&got); err != nil {
		return nil, nil, err
	}
	if kpI, err = tp.toResp.BeginSession(); err != nil {
		t.Fatalf("initiator BeginSession: %v", err)
	}
	if kpR, err = tp.toInit.BeginSession(); err != nil {
		t.Fatalf("responder BeginSession: %v", err)
	}
	return kpI, kpR, nil
}

// exchange sends a packet from a to b over the wire form and checks it
// arrives intact.
func exchange(t *testing.T, a, b *Keypair, packet []byte) []byte {
	t.Helper()
	m, err := a.Encrypt(packet, 0)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := m.MarshalBinary()
	var got Transport
	if err := got.UnmarshalBinary(wire); err != nil {
		t.Fatal(err)
	}
	plain, err := b.Decrypt(nil, &got)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(plain[:len(packet)], packet) || len(plain)%PaddingMultiple != 0 {
		t.Fatalf("decrypted %x, want %x padded to 16", plain, packet)
	}
	if !bytes.Equal(plain[len(packet):], make([]byte, len(plain)-len(packet))) {
		t.Fatalf("padding not zero: %x", plain[len(packet):])
	}
	return wire
}

func testHandshake(t *testing.T, psk [KeySize]byte) {
	tp := newTestPair(t, 1, psk, psk)
	kpI, kpR, err := tp.run(t, testNow, testWall)
	if err != nil {
		t.Fatalf("ConsumeResponse: %v", err)
	}
	if kpI.send != kpR.recv || kpI.recv != kpR.send || kpI.send == kpI.recv {
		t.Fatal("transport keys do not pair up")
	}
	if !kpI.Initiator || kpR.Initiator {
		t.Error("initiator flags are wrong")
	}
	if kpI.LocalIndex != tp.initIdx || kpI.RemoteIndex != tp.respIdx ||
		kpR.LocalIndex != tp.respIdx || kpR.RemoteIndex != tp.initIdx {
		t.Errorf("indices: initiator %#x→%#x, responder %#x→%#x", kpI.LocalIndex, kpI.RemoteIndex, kpR.LocalIndex, kpR.RemoteIndex)
	}

	wire := exchange(t, kpI, kpR, []byte("hello from the initiator"))
	exchange(t, kpR, kpI, []byte("hello back"))
	if ka := exchange(t, kpI, kpR, nil); len(ka) != TransportMinSize {
		t.Errorf("keepalive is %d bytes, want 32", len(ka))
	}
	if kpI.Sent() != 2 {
		t.Errorf("initiator sent counter %d, want 2", kpI.Sent())
	}

	// A replayed transport message is authentic but must be rejected.
	var again Transport
	again.UnmarshalBinary(wire)
	if _, err := kpR.Decrypt(nil, &again); !errors.Is(err, ErrReplay) {
		t.Errorf("replayed transport: %v, want ErrReplay", err)
	}
	// A forged one must fail authentication without moving the window.
	again.Counter = 1000
	if _, err := kpR.Decrypt(nil, &again); !errors.Is(err, ErrDecrypt) {
		t.Errorf("forged counter: %v, want ErrDecrypt", err)
	}
	if kpR.replay.last != 1 {
		t.Errorf("window moved to %d by a forged message", kpR.replay.last)
	}

	// Handshake state is zeroed: no second session from the same handshake.
	if _, err := tp.toResp.BeginSession(); !errors.Is(err, ErrHandshakeState) {
		t.Errorf("second BeginSession: %v, want ErrHandshakeState", err)
	}
}

func TestHandshakeWithoutPSK(t *testing.T) {
	testHandshake(t, [KeySize]byte{})
}

func TestHandshakeWithPSK(t *testing.T) {
	var psk [KeySize]byte
	for i := range psk {
		psk[i] = byte(0xa0 + i)
	}
	testHandshake(t, psk)
}

func TestHandshakePSKMismatch(t *testing.T) {
	tp := newTestPair(t, 2, [KeySize]byte{1}, [KeySize]byte{2})
	if _, _, err := tp.run(t, testNow, testWall); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("mismatched PSK: %v, want ErrDecrypt", err)
	}
	// The failed response must leave the initiator waiting, not broken.
	if tp.toResp.hs.state != stateInitiationCreated {
		t.Errorf("state after a bad response = %d", tp.toResp.hs.state)
	}
}

func TestHandshakeDifferentSessionsDiffer(t *testing.T) {
	tp := newTestPair(t, 3, [KeySize]byte{}, [KeySize]byte{})
	kp1, _, err := tp.run(t, testNow, testWall)
	if err != nil {
		t.Fatal(err)
	}
	kp2, _, err := tp.run(t, testNow+5e9, testWall+5e9)
	if err != nil {
		t.Fatal(err)
	}
	if kp1.send == kp2.send {
		t.Error("two handshakes produced the same transport key")
	}
}

func TestInitiationReplayRejected(t *testing.T) {
	tp := newTestPair(t, 4, [KeySize]byte{}, [KeySize]byte{})
	b := tp.initiation(t, testNow, testWall)
	if err := tp.consumeInitiation(b, testNow); err != nil {
		t.Fatalf("first initiation: %v", err)
	}
	// The same bytes a second later: the timestamp is not newer.
	if err := tp.consumeInitiation(b, testNow+1e9); !errors.Is(err, ErrStaleTimestamp) {
		t.Fatalf("replayed initiation: %v, want ErrStaleTimestamp", err)
	}
	// A fresh initiation with an older clock is also stale.
	old := tp.initiation(t, testNow+2e9, testWall-1e9)
	if err := tp.consumeInitiation(old, testNow+2e9); !errors.Is(err, ErrStaleTimestamp) {
		t.Fatalf("older timestamp: %v, want ErrStaleTimestamp", err)
	}
	// Within the same 2^24 ns whitening step the label is equal: stale.
	same := tp.initiation(t, testNow+3e9, testWall+1)
	if err := tp.consumeInitiation(same, testNow+3e9); !errors.Is(err, ErrStaleTimestamp) {
		t.Fatalf("equal timestamp: %v, want ErrStaleTimestamp", err)
	}
	// A newer timestamp is accepted…
	newer := tp.initiation(t, testNow+4e9, testWall+1e9)
	if err := tp.consumeInitiation(newer, testNow+4e9); err != nil {
		t.Fatalf("newer timestamp: %v", err)
	}
	// …but not within 20 ms of the previous accepted one.
	flood := tp.initiation(t, testNow+4e9+10e6, testWall+2e9)
	if err := tp.consumeInitiation(flood, testNow+4e9+10e6); !errors.Is(err, ErrFlood) {
		t.Fatalf("initiation 10 ms later: %v, want ErrFlood", err)
	}
	if err := tp.consumeInitiation(flood, testNow+4e9+20e6); err != nil {
		t.Fatalf("initiation 20 ms later: %v", err)
	}
}

func TestInitiationUnknownPeerAndTampering(t *testing.T) {
	tp := newTestPair(t, 5, [KeySize]byte{}, [KeySize]byte{})
	b := tp.initiation(t, testNow, testWall)
	var m Initiation
	m.UnmarshalBinary(b)
	nobody := func([KeySize]byte) *Peer { return nil }
	if _, err := tp.lr.ConsumeInitiation(&m, testNow, nobody); !errors.Is(err, ErrUnknownPeer) {
		t.Errorf("unknown peer: %v, want ErrUnknownPeer", err)
	}
	for _, off := range []int{8, 40, 88, 115} { // ephemeral, static, timestamp
		bad := bytes.Clone(b)
		bad[off] ^= 1
		if err := tp.consumeInitiation(bad, testNow); err == nil {
			t.Errorf("initiation with byte %d flipped was accepted", off)
		}
	}
	if err := tp.consumeInitiation(b, testNow); err != nil {
		t.Errorf("failed attempts must not change the peer state: %v", err)
	}
}

func TestResponseIndexAndState(t *testing.T) {
	tp := newTestPair(t, 6, [KeySize]byte{}, [KeySize]byte{})
	if _, err := tp.toInit.CreateResponse(tp.rnd, testNow, 1); !errors.Is(err, ErrHandshakeState) {
		t.Errorf("response without initiation: %v, want ErrHandshakeState", err)
	}
	b := tp.initiation(t, testNow, testWall)
	if err := tp.consumeInitiation(b, testNow); err != nil {
		t.Fatal(err)
	}
	resp, err := tp.toInit.CreateResponse(tp.rnd, testNow, tp.respIdx)
	if err != nil {
		t.Fatal(err)
	}
	wrong := *resp
	wrong.Receiver++
	if err := tp.toResp.ConsumeResponse(&wrong); !errors.Is(err, ErrIndex) {
		t.Errorf("wrong receiver index: %v, want ErrIndex", err)
	}
	if err := tp.toResp.ConsumeResponse(resp); err != nil {
		t.Fatal(err)
	}
	if err := tp.toResp.ConsumeResponse(resp); !errors.Is(err, ErrHandshakeState) {
		t.Errorf("second response: %v, want ErrHandshakeState", err)
	}
}

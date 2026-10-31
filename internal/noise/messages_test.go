package noise

import (
	"bytes"
	"errors"
	"testing"
)

// TestCritProtocolConstants compares the four labels byte by byte with the
// literals published on https://www.wireguard.com/protocol/ (pinned in
// vault/RESEARCH.md) and checks the message types.
func TestCritProtocolConstants(t *testing.T) {
	cases := []struct {
		name, got, want string
		size            int
	}{
		{"CONSTRUCTION", Construction, "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s", 37},
		{"IDENTIFIER", Identifier, "WireGuard v1 zx2c4 Jason@zx2c4.com", 34},
		{"LABEL_MAC1", LabelMAC1, "mac1----", 8},
		{"LABEL_COOKIE", LabelCookie, "cookie--", 8},
	}
	for _, c := range cases {
		if len(c.want) != c.size {
			t.Fatalf("%s: published literal is %d bytes, want %d", c.name, len(c.want), c.size)
		}
		if !bytes.Equal([]byte(c.got), []byte(c.want)) {
			t.Errorf("%s = %q (%d bytes), want %q (%d bytes)", c.name, c.got, len(c.got), c.want, c.size)
		}
	}
	types := []struct {
		name      string
		got, want int
	}{
		{"initiation", TypeInitiation, 1},
		{"response", TypeResponse, 2},
		{"cookie reply", TypeCookieReply, 3},
		{"transport", TypeTransport, 4},
	}
	for _, c := range types {
		if c.got != c.want {
			t.Errorf("%s type = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// TestCritMessageSizes checks the serialized size of the four messages:
// 148, 92, 64 and 16 + padded payload + 16.
func TestCritMessageSizes(t *testing.T) {
	fixed := []struct {
		name string
		m    interface{ MarshalBinary() ([]byte, error) }
		want int
		typ  byte
	}{
		{"initiation", &Initiation{}, 148, TypeInitiation},
		{"response", &Response{}, 92, TypeResponse},
		{"cookie reply", &CookieReply{}, 64, TypeCookieReply},
	}
	for _, c := range fixed {
		b, err := c.m.MarshalBinary()
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(b) != c.want {
			t.Errorf("%s: %d bytes, want %d", c.name, len(b), c.want)
		}
		if !bytes.Equal(b[:4], []byte{c.typ, 0, 0, 0}) {
			t.Errorf("%s: header % x, want %02x 00 00 00", c.name, b[:4], c.typ)
		}
	}
	if InitiationSize != 148 || ResponseSize != 92 || CookieReplySize != 64 || TransportMinSize != 32 {
		t.Errorf("size constants %d, %d, %d, %d; want 148, 92, 64, 32",
			InitiationSize, ResponseSize, CookieReplySize, TransportMinSize)
	}

	k := &Keypair{RemoteIndex: 7}
	for _, n := range []int{0, 1, 15, 16, 17, 100, 1420} {
		m, err := k.Encrypt(make([]byte, n), 0)
		if err != nil {
			t.Fatal(err)
		}
		b, err := m.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		padded := (n + 15) / 16 * 16
		if want := 16 + padded + 16; len(b) != want {
			t.Errorf("transport with %d-byte payload: %d bytes, want %d", n, len(b), want)
		}
		if !bytes.Equal(b[:4], []byte{TypeTransport, 0, 0, 0}) {
			t.Errorf("transport: header % x", b[:4])
		}
	}
}

func TestMessageRoundTrip(t *testing.T) {
	in := Initiation{Sender: 0x01020304}
	for i := range in.Ephemeral {
		in.Ephemeral[i] = byte(i)
	}
	in.Static[47], in.Timestamp[27], in.MAC1[0], in.MAC2[15] = 1, 2, 3, 4
	b, _ := in.MarshalBinary()
	if !bytes.Equal(b[4:8], []byte{4, 3, 2, 1}) {
		t.Errorf("sender index not little-endian: % x", b[4:8])
	}
	var out Initiation
	if err := out.UnmarshalBinary(b); err != nil || out != in {
		t.Errorf("initiation round trip: %v, %+v", err, out)
	}

	resp := Response{Sender: 5, Receiver: 6, Empty: [16]byte{7}, MAC2: [16]byte{8}}
	b, _ = resp.MarshalBinary()
	var resp2 Response
	if err := resp2.UnmarshalBinary(b); err != nil || resp2 != resp {
		t.Errorf("response round trip: %v, %+v", err, resp2)
	}

	cr := CookieReply{Receiver: 9, Nonce: [24]byte{10}, Cookie: [32]byte{11}}
	b, _ = cr.MarshalBinary()
	var cr2 CookieReply
	if err := cr2.UnmarshalBinary(b); err != nil || cr2 != cr {
		t.Errorf("cookie reply round trip: %v, %+v", err, cr2)
	}

	tr := Transport{Receiver: 12, Counter: 0x0102030405060708, Content: bytes.Repeat([]byte{13}, 32)}
	b, _ = tr.MarshalBinary()
	if !bytes.Equal(b[8:16], []byte{8, 7, 6, 5, 4, 3, 2, 1}) {
		t.Errorf("counter not little-endian: % x", b[8:16])
	}
	var tr2 Transport
	if err := tr2.UnmarshalBinary(b); err != nil || tr2.Receiver != 12 || tr2.Counter != tr.Counter || !bytes.Equal(tr2.Content, tr.Content) {
		t.Errorf("transport round trip: %v, %+v", err, tr2)
	}
}

func TestMessageRejectsBadHeaders(t *testing.T) {
	b, _ := (&Initiation{}).MarshalBinary()
	var m Initiation
	if err := m.UnmarshalBinary(b[:147]); !errors.Is(err, ErrMessageSize) {
		t.Errorf("147-byte initiation: %v, want ErrMessageSize", err)
	}
	b[2] = 1
	if err := m.UnmarshalBinary(b); !errors.Is(err, ErrMessageType) {
		t.Errorf("nonzero reserved byte: %v, want ErrMessageType", err)
	}
	b[2], b[0] = 0, TypeResponse
	if err := m.UnmarshalBinary(b); !errors.Is(err, ErrMessageType) {
		t.Errorf("wrong type: %v, want ErrMessageType", err)
	}
	var tr Transport
	if err := tr.UnmarshalBinary(append([]byte{TypeTransport, 0, 0, 0}, make([]byte, 27)...)); !errors.Is(err, ErrMessageSize) {
		t.Errorf("31-byte transport: %v, want ErrMessageSize", err)
	}
	if MessageType(nil) != 0 || MessageType([]byte{5, 0, 0, 0}) != 0 {
		t.Error("MessageType accepted an invalid header")
	}
}

func TestTAI64N(t *testing.T) {
	ts := TAI64N(0)
	want := []byte{0x40, 0, 0, 0, 0, 0, 0, 0x0a, 0, 0, 0, 0}
	if !bytes.Equal(ts[:], want) {
		t.Errorf("TAI64N(0) = % x, want % x", ts[:], want)
	}
	ts = TAI64N(1_700_000_000*1e9 + 123_456_789)
	// 123456789 rounded down to a multiple of 2^24 is 117440512 = 0x07000000.
	want = []byte{0x40, 0, 0, 0, 0x65, 0x53, 0xf1, 0x0a, 0x07, 0, 0, 0}
	if !bytes.Equal(ts[:], want) {
		t.Errorf("TAI64N = % x, want % x", ts[:], want)
	}
	if TAI64N(1e9+1<<24-1) != TAI64N(1e9) {
		t.Error("nanoseconds within one 2^24 ns step must give the same label")
	}
	if !TAI64N(1e9+1<<24).After(TAI64N(1e9)) || TAI64N(1e9).After(TAI64N(1e9)) {
		t.Error("After does not order labels strictly")
	}
}

func TestTransportPaddingMTU(t *testing.T) {
	cases := []struct{ n, mtu, want int }{
		{0, 0, 0}, {1, 0, 15}, {16, 0, 0}, {1419, 1420, 1}, {1420, 1420, 0}, {1410, 1420, 10}, {1500, 1420, 0},
	}
	for _, c := range cases {
		if got := paddingLen(c.n, c.mtu); got != c.want {
			t.Errorf("paddingLen(%d, %d) = %d, want %d", c.n, c.mtu, got, c.want)
		}
	}
}

package blake2s

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func unhex(t *testing.T, name, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%s: bad hex: %v", name, err)
	}
	return b
}

type rfc7693File struct {
	AppendixB struct {
		Name, Input, Digest string
	} `json:"appendix_b"`
	AppendixE struct {
		Name   string
		MdLen  []int `json:"md_len"`
		InLen  []int `json:"in_len"`
		Result string
	} `json:"appendix_e"`
}

// selftestSeq is selftest_seq of RFC 7693 Appendix E: a Fibonacci generator
// over uint32 seeded with 0xDEAD4BAD * seed.
func selftestSeq(n int, seed uint32) []byte {
	out := make([]byte, n)
	a, b := 0xDEAD4BAD*seed, uint32(1)
	for i := range out {
		t := a + b
		a, b = b, t
		out[i] = byte(t >> 24)
	}
	return out
}

func TestCritVectorsRFC7693(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "rfc7693.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f rfc7693File
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("rfc7693.json: %v", err)
	}

	b := f.AppendixB
	in, want := unhex(t, b.Name, b.Input), unhex(t, b.Name, b.Digest)
	if got := Sum256(in); !bytes.Equal(got[:], want) {
		t.Errorf("%s: Sum256: got %x, want %x", b.Name, got, want)
	}
	h := New256()
	h.Write(in)
	if got := h.Sum(nil); !bytes.Equal(got, want) {
		t.Errorf("%s: New256: got %x, want %x", b.Name, got, want)
	}

	// Appendix E: hash every unkeyed and keyed digest into a grand hash.
	e := f.AppendixE
	if len(e.MdLen) != 4 || len(e.InLen) != 6 {
		t.Fatalf("%s: got %d output and %d input lengths; want 4 and 6", e.Name, len(e.MdLen), len(e.InLen))
	}
	grand := New256()
	for _, outlen := range e.MdLen {
		for _, inlen := range e.InLen {
			msg := selftestSeq(inlen, uint32(inlen))
			for _, key := range [][]byte{nil, selftestSeq(outlen, uint32(outlen))} {
				d, err := New(outlen, key)
				if err != nil {
					t.Fatalf("New(%d, %d-byte key): %v", outlen, len(key), err)
				}
				d.Write(msg)
				md := d.Sum(nil)
				if len(md) != outlen || d.Size() != outlen {
					t.Fatalf("New(%d, %d-byte key): digest of %d bytes, Size %d", outlen, len(key), len(md), d.Size())
				}
				grand.Write(md)
			}
		}
	}
	if got, want := grand.Sum(nil), unhex(t, e.Name, e.Result); !bytes.Equal(got, want) {
		t.Errorf("%s: grand hash: got %x, want %x", e.Name, got, want)
	}
}

// TestMAC checks MAC with the two key sizes WireGuard uses (32 bytes for
// mac1, 16 for mac2) against values from Python's hashlib.blake2s
// (digest_size=16, key=...), computed independently on 2026-10-31.
func TestMAC(t *testing.T) {
	msg := []byte("malla-wg mac1 test message")
	for _, tc := range []struct {
		keyLen int
		want   string
	}{
		{32, "80e7c6927259c5736c0d3e4926056b67"},
		{16, "07eb1f78eceb1de76cea156f510b9450"},
	} {
		key := make([]byte, tc.keyLen)
		for i := range key {
			key[i] = byte(i)
		}
		want := unhex(t, "MAC", tc.want)
		if got := MAC(key, msg); !bytes.Equal(got[:], want) {
			t.Errorf("MAC with %d-byte key: got %x, want %x", tc.keyLen, got, want)
		}
		h, err := New(MACSize, key)
		if err != nil {
			t.Fatal(err)
		}
		for rest := msg; len(rest) > 0; {
			n := min(len(rest), 5)
			h.Write(rest[:n])
			rest = rest[n:]
		}
		if got := h.Sum(nil); !bytes.Equal(got, want) {
			t.Errorf("New(16, %d-byte key) with 5-byte writes: got %x, want %x", tc.keyLen, got, want)
		}
	}
}

// TestStreaming checks that write splits, Sum and Reset do not change the
// digest, including across block boundaries and with a key block.
func TestStreaming(t *testing.T) {
	msg := selftestSeq(300, 7)
	key := selftestSeq(32, 9)
	for _, n := range []int{0, 1, 63, 64, 65, 128, 129, 300} {
		want := MAC(key, msg[:n])
		h, err := New(MACSize, key)
		if err != nil {
			t.Fatal(err)
		}
		h.Write([]byte("garbage"))
		h.Reset()
		for i := 0; i < n; i++ {
			h.Write(msg[i : i+1])
			_ = h.Sum(nil)
		}
		if got := h.Sum([]byte{0xff}); got[0] != 0xff || !bytes.Equal(got[1:], want[:]) {
			t.Errorf("%d bytes one at a time: got %x, want ff%x", n, got, want)
		}
	}
}

func TestSizesRejected(t *testing.T) {
	for _, n := range []int{-1, 0, 33, 64} {
		if _, err := New(n, nil); !errors.Is(err, ErrSize) {
			t.Errorf("New(%d, nil): got %v, want ErrSize", n, err)
		}
	}
	if _, err := New(Size, make([]byte, 33)); !errors.Is(err, ErrKeySize) {
		t.Errorf("New with 33-byte key: got %v, want ErrKeySize", err)
	}
	defer func() {
		if recover() == nil {
			t.Error("MAC with 33-byte key did not panic")
		}
	}()
	MAC(make([]byte, 33), nil)
}

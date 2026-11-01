package hkdf

import (
	"bytes"
	"crypto/sha256" // only as the hash under test vectors: RFC 5869 Appendix A uses SHA-256
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/CesarManzoCode/malla-wg/internal/blake2s"
)

func unhex(t *testing.T, name, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%s: bad hex: %v", name, err)
	}
	return b
}

type rfc5869File struct {
	Cases []struct {
		Name, IKM, Salt, Info string
		L                     int
		PRK, OKM              string
	}
}

// TestCritVectorsRFC5869 runs this package's HMAC and HKDF over SHA-256 on
// test cases 1 to 3 of RFC 5869 Appendix A.
func TestCritVectorsRFC5869(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "rfc5869.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f rfc5869File
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("rfc5869.json: %v", err)
	}
	if len(f.Cases) != 3 {
		t.Fatalf("rfc5869.json: got %d cases, want 3", len(f.Cases))
	}
	for _, c := range f.Cases {
		ikm, salt, info := unhex(t, c.Name, c.IKM), unhex(t, c.Name, c.Salt), unhex(t, c.Name, c.Info)
		wantPRK, wantOKM := unhex(t, c.Name, c.PRK), unhex(t, c.Name, c.OKM)
		prk := Extract(sha256.New, salt, ikm)
		if !bytes.Equal(prk, wantPRK) {
			t.Errorf("%s: PRK: got %x, want %x", c.Name, prk, wantPRK)
		}
		okm, err := Expand(sha256.New, wantPRK, info, c.L)
		if err != nil || !bytes.Equal(okm, wantOKM) {
			t.Errorf("%s: OKM: got %x, %v; want %x", c.Name, okm, err, wantOKM)
		}
	}
}

// hmacByHand is RFC 2104 written out over the own BLAKE2s-256 with its
// 64-byte block: H(K ^ opad || H(K ^ ipad || text)).
func hmacByHand(key, text []byte) [32]byte {
	if len(key) > 64 {
		k := blake2s.Sum256(key)
		key = k[:]
	}
	var ipad, opad [64]byte
	copy(ipad[:], key)
	copy(opad[:], key)
	for i := range ipad {
		ipad[i] ^= 0x36
		opad[i] ^= 0x5c
	}
	inner := blake2s.Sum256(append(ipad[:], text...))
	return blake2s.Sum256(append(opad[:], inner[:]...))
}

// TestHMACBlake2s checks HMAC-BLAKE2s against RFC 2104 computed by hand and
// against values from Python's hmac.new(key, msg, hashlib.blake2s), computed
// independently on 2026-10-31, for a 32-byte key and a 100-byte key (hashed
// first because it exceeds the block).
func TestHMACBlake2s(t *testing.T) {
	msg := []byte("malla-wg hmac test")
	for _, tc := range []struct {
		keyLen int
		want   string
	}{
		{32, "676fc4e68b02d448dc2970552f57dda5ac6fafea9c1fab87462ac1116bfd112f"},
		{100, "6f74765f266c4f226ac50900e78d67d3002c468b5c6c36f57cbb5e82e8a3b071"},
	} {
		key := make([]byte, tc.keyLen)
		for i := range key {
			key[i] = byte(i)
		}
		byHand := hmacByHand(key, msg)
		got := HMACBlake2s(key, msg[:5], msg[5:])
		if got != byHand {
			t.Errorf("%d-byte key: HMACBlake2s %x, by hand %x", tc.keyLen, got, byHand)
		}
		if want := unhex(t, "HMAC-BLAKE2s", tc.want); !bytes.Equal(got[:], want) {
			t.Errorf("%d-byte key: HMACBlake2s %x, want %x", tc.keyLen, got, want)
		}

		m := NewHMAC(blake2s.New256, key)
		m.Write([]byte("garbage"))
		m.Reset()
		m.Write(msg)
		_ = m.Sum(nil)
		if s := m.Sum(nil); !bytes.Equal(s, byHand[:]) || m.Size() != 32 || m.BlockSize() != 64 {
			t.Errorf("%d-byte key: NewHMAC after Reset: %x (Size %d, BlockSize %d), want %x",
				tc.keyLen, s, m.Size(), m.BlockSize(), byHand)
		}
	}
}

// TestKDFMatchesHKDF checks that KDF1..KDF3, written as on the WireGuard
// protocol page, equal generic HKDF over HMAC-BLAKE2s with the chaining key
// as salt and empty info, and that each KDFn is a prefix of the next.
func TestKDFMatchesHKDF(t *testing.T) {
	key := bytes.Repeat([]byte{0xa5}, 32)
	for _, input := range [][]byte{nil, []byte("input"), bytes.Repeat([]byte{7}, 200)} {
		prk := Extract(blake2s.New256, key, input)
		okm, err := Expand(blake2s.New256, prk, nil, 96)
		if err != nil {
			t.Fatal(err)
		}
		a1, a2, a3 := KDF3(key, input)
		if !bytes.Equal(okm, append(append(a1[:], a2[:]...), a3[:]...)) {
			t.Errorf("%d-byte input: KDF3 differs from HKDF", len(input))
		}
		b1, b2 := KDF2(key, input)
		c1 := KDF1(key, input)
		if b1 != a1 || b2 != a2 || c1 != a1 {
			t.Errorf("%d-byte input: KDF1/KDF2 are not prefixes of KDF3", len(input))
		}
	}
}

func TestExpandLength(t *testing.T) {
	prk := make([]byte, 32)
	if okm, err := Expand(blake2s.New256, prk, nil, 255*32); err != nil || len(okm) != 255*32 {
		t.Errorf("Expand 255*32: got %d bytes, %v", len(okm), err)
	}
	for _, n := range []int{-1, 255*32 + 1} {
		if _, err := Expand(blake2s.New256, prk, nil, n); !errors.Is(err, ErrLength) {
			t.Errorf("Expand %d: got %v, want ErrLength", n, err)
		}
	}
}

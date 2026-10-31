package chachapoly

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func unhex(t *testing.T, name, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%s: bad hex: %v", name, err)
	}
	return b
}

func key32(t *testing.T, name, s string) *[KeySize]byte {
	t.Helper()
	b := unhex(t, name, s)
	if len(b) != KeySize {
		t.Fatalf("%s: key is %d bytes", name, len(b))
	}
	return (*[KeySize]byte)(b)
}

func nonce12(t *testing.T, name, s string) *[NonceSize]byte {
	t.Helper()
	b := unhex(t, name, s)
	if len(b) != NonceSize {
		t.Fatalf("%s: nonce is %d bytes", name, len(b))
	}
	return (*[NonceSize]byte)(b)
}

type rfc8439File struct {
	ChaCha20Block []struct {
		Name, Key, Nonce string
		Counter          uint32
		Block            string
	} `json:"chacha20_block"`
	ChaCha20Encrypt []struct {
		Name, Key, Nonce      string
		Counter               uint32
		Plaintext, Ciphertext string
	} `json:"chacha20_encrypt"`
	Poly1305 []struct {
		Name, Key, Msg, Tag string
	} `json:"poly1305"`
	Poly1305Keygen []struct {
		Name, Key, Nonce, Otk string
	} `json:"poly1305_keygen"`
	AEAD []struct {
		Name, Key, Nonce, AAD, Plaintext, Ciphertext, Tag string
	} `json:"aead"`
}

func TestCritVectorsRFC8439(t *testing.T) {
	var f rfc8439File
	readJSON(t, filepath.Join("testdata", "rfc8439.json"), &f)
	// §2.3.2 + A.1 (5), §2.4.2 + A.2 (3), §2.5.2 + A.3 (11), §2.6.2 + A.4 (3), §2.8.2 + A.5.
	if len(f.ChaCha20Block) != 6 || len(f.ChaCha20Encrypt) != 4 || len(f.Poly1305) != 12 ||
		len(f.Poly1305Keygen) != 4 || len(f.AEAD) != 2 {
		t.Fatalf("rfc8439.json: got %d/%d/%d/%d/%d vectors; want 6/4/12/4/2",
			len(f.ChaCha20Block), len(f.ChaCha20Encrypt), len(f.Poly1305), len(f.Poly1305Keygen), len(f.AEAD))
	}

	for _, v := range f.ChaCha20Block {
		got := chachaBlock(key32(t, v.Name, v.Key), v.Counter, nonce12(t, v.Name, v.Nonce))
		if want := unhex(t, v.Name, v.Block); !bytes.Equal(got[:], want) {
			t.Errorf("%s: block: got %x, want %x", v.Name, got, want)
		}
	}

	for _, v := range f.ChaCha20Encrypt {
		key, nonce := key32(t, v.Name, v.Key), nonce12(t, v.Name, v.Nonce)
		pt, want := unhex(t, v.Name, v.Plaintext), unhex(t, v.Name, v.Ciphertext)
		got := make([]byte, len(pt))
		xorKeyStream(got, pt, key, v.Counter, nonce)
		if !bytes.Equal(got, want) {
			t.Errorf("%s: encrypt: got %x, want %x", v.Name, got, want)
		}
		xorKeyStream(got, got, key, v.Counter, nonce)
		if !bytes.Equal(got, pt) {
			t.Errorf("%s: in-place decrypt: got %x, want %x", v.Name, got, pt)
		}
	}

	for _, v := range f.Poly1305 {
		key := key32(t, v.Name, v.Key)
		msg, want := unhex(t, v.Name, v.Msg), unhex(t, v.Name, v.Tag)
		if got := poly1305Sum(key, msg); !bytes.Equal(got[:], want) {
			t.Errorf("%s: tag: got %x, want %x", v.Name, got, want)
		}
		// The same message fed in uneven pieces must give the same tag.
		p := newPoly1305(key)
		for rest := msg; len(rest) > 0; {
			n := min(len(rest), 7)
			p.write(rest[:n])
			rest = rest[n:]
		}
		if got := p.finish(); !bytes.Equal(got[:], want) {
			t.Errorf("%s: tag with 7-byte writes: got %x, want %x", v.Name, got, want)
		}
	}

	for _, v := range f.Poly1305Keygen {
		block := chachaBlock(key32(t, v.Name, v.Key), 0, nonce12(t, v.Name, v.Nonce))
		if want := unhex(t, v.Name, v.Otk); !bytes.Equal(block[:32], want) {
			t.Errorf("%s: one-time key: got %x, want %x", v.Name, block[:32], want)
		}
	}

	for _, v := range f.AEAD {
		key, nonce, aad := unhex(t, v.Name, v.Key), unhex(t, v.Name, v.Nonce), unhex(t, v.Name, v.AAD)
		pt := unhex(t, v.Name, v.Plaintext)
		want := append(unhex(t, v.Name, v.Ciphertext), unhex(t, v.Name, v.Tag)...)
		sealed, err := Seal(nil, key, nonce, pt, aad)
		if err != nil || !bytes.Equal(sealed, want) {
			t.Errorf("%s: Seal: got %x, %v; want %x", v.Name, sealed, err, want)
		}
		opened, err := Open(nil, key, nonce, want, aad)
		if err != nil || !bytes.Equal(opened, pt) {
			t.Errorf("%s: Open: got %x, %v; want %x", v.Name, opened, err, pt)
		}
		bad := bytes.Clone(want)
		bad[len(bad)-1] ^= 1
		if _, err := Open(nil, key, nonce, bad, aad); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: Open with a flipped tag bit: got %v, want ErrOpen", v.Name, err)
		}
	}
}

func TestSizesRejected(t *testing.T) {
	key := make([]byte, KeySize)
	for _, n := range []int{0, 8, 11, 13, 16, 24} {
		if _, err := Seal(nil, key, make([]byte, n), nil, nil); !errors.Is(err, ErrNonceSize) {
			t.Errorf("Seal with %d-byte nonce: got %v, want ErrNonceSize", n, err)
		}
		if _, err := Open(nil, key, make([]byte, n), make([]byte, Overhead), nil); !errors.Is(err, ErrNonceSize) {
			t.Errorf("Open with %d-byte nonce: got %v, want ErrNonceSize", n, err)
		}
	}
	for _, n := range []int{0, 12, 16, 23, 25, 32} {
		if _, err := XSeal(nil, key, make([]byte, n), nil, nil); !errors.Is(err, ErrNonceSize) {
			t.Errorf("XSeal with %d-byte nonce: got %v, want ErrNonceSize", n, err)
		}
		if _, err := XOpen(nil, key, make([]byte, n), make([]byte, Overhead), nil); !errors.Is(err, ErrNonceSize) {
			t.Errorf("XOpen with %d-byte nonce: got %v, want ErrNonceSize", n, err)
		}
	}
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := Seal(nil, make([]byte, n), make([]byte, NonceSize), nil, nil); !errors.Is(err, ErrKeySize) {
			t.Errorf("Seal with %d-byte key: got %v, want ErrKeySize", n, err)
		}
		if _, err := XSeal(nil, make([]byte, n), make([]byte, NonceSizeX), nil, nil); !errors.Is(err, ErrKeySize) {
			t.Errorf("XSeal with %d-byte key: got %v, want ErrKeySize", n, err)
		}
	}
}

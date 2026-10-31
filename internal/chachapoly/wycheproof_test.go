package chachapoly

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"
)

type wycheproofAEAD struct {
	Algorithm     string
	NumberOfTests int
	TestGroups    []struct {
		IvSize  int
		KeySize int
		TagSize int
		Tests   []struct {
			TcID    int `json:"tcId"`
			Comment string
			Key     string
			Iv      string
			Aad     string
			Msg     string
			Ct      string
			Tag     string
			Result  string
		}
	}
}

type aeadFunc func(dst, key, nonce, text, ad []byte) ([]byte, error)

// runWycheproofAEAD checks that every valid vector seals to ct||tag and opens
// back to msg, and that Open rejects every invalid one, including the groups
// with unsupported nonce sizes.
func runWycheproofAEAD(t *testing.T, file, algorithm string, seal, open aeadFunc) {
	var f wycheproofAEAD
	readJSON(t, filepath.Join("testdata", "wycheproof", file), &f)
	if f.Algorithm != algorithm {
		t.Fatalf("%s: algorithm %q, want %q", file, f.Algorithm, algorithm)
	}

	ran := 0
	for _, g := range f.TestGroups {
		for _, tc := range g.Tests {
			ran++
			name := fmt.Sprintf("tcId %d (%s, %d-bit nonce)", tc.TcID, tc.Comment, g.IvSize)
			key, nonce := unhex(t, name, tc.Key), unhex(t, name, tc.Iv)
			aad, msg := unhex(t, name, tc.Aad), unhex(t, name, tc.Msg)
			sealed := append(unhex(t, name, tc.Ct), unhex(t, name, tc.Tag)...)

			switch tc.Result {
			case "valid":
				got, err := seal(nil, key, nonce, msg, aad)
				if err != nil || !bytes.Equal(got, sealed) {
					t.Errorf("%s: Seal: got %x, %v; want %x", name, got, err, sealed)
				}
				pt, err := open(nil, key, nonce, sealed, aad)
				if err != nil || !bytes.Equal(pt, msg) {
					t.Errorf("%s: Open: got %x, %v; want %x", name, pt, err, msg)
				}
			case "invalid":
				if pt, err := open(nil, key, nonce, sealed, aad); err == nil {
					t.Errorf("%s: Open accepted an invalid vector, plaintext %x", name, pt)
				}
			default:
				t.Fatalf("%s: unexpected result %q", name, tc.Result)
			}
		}
	}
	if ran != f.NumberOfTests {
		t.Errorf("%s: ran %d tests, file declares %d", file, ran, f.NumberOfTests)
	}
}

func TestCritWycheproofChaCha20Poly1305(t *testing.T) {
	runWycheproofAEAD(t, "chacha20_poly1305_test.json", "CHACHA20-POLY1305", Seal, Open)
}

func TestCritWycheproofXChaCha20Poly1305(t *testing.T) {
	runWycheproofAEAD(t, "xchacha20_poly1305_test.json", "XCHACHA20-POLY1305", XSeal, XOpen)
}

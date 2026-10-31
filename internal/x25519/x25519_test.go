package x25519

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

func hex32(t *testing.T, name, s string) [32]byte {
	t.Helper()
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("%s: bad 32-byte hex %q", name, s)
	}
	copy(out[:], b)
	return out
}

type rfc7748File struct {
	ScalarMult []struct {
		Name, Scalar, U, Out string
	} `json:"scalar_mult"`
	Iterated []struct {
		Name       string
		Start      string
		Iterations int
		Out        string
	} `json:"iterated"`
	DH []struct {
		Name         string
		AlicePrivate string `json:"alice_private"`
		AlicePublic  string `json:"alice_public"`
		BobPrivate   string `json:"bob_private"`
		BobPublic    string `json:"bob_public"`
		Shared       string
	} `json:"dh"`
}

func TestCritVectorsRFC7748(t *testing.T) {
	var f rfc7748File
	readJSON(t, filepath.Join("testdata", "rfc7748.json"), &f)
	if len(f.ScalarMult) != 2 || len(f.Iterated) != 2 || len(f.DH) != 1 {
		t.Fatalf("rfc7748.json: got %d scalar_mult, %d iterated, %d dh vectors; want 2, 2, 1",
			len(f.ScalarMult), len(f.Iterated), len(f.DH))
	}

	for _, v := range f.ScalarMult {
		got, err := X25519(hex32(t, v.Name, v.Scalar), hex32(t, v.Name, v.U))
		if err != nil {
			t.Errorf("%s: %v", v.Name, err)
			continue
		}
		if want := hex32(t, v.Name, v.Out); got != want {
			t.Errorf("%s: got %x, want %x", v.Name, got, want)
		}
	}

	for _, v := range f.Iterated {
		k := hex32(t, v.Name, v.Start)
		u := k
		for i := 0; i < v.Iterations; i++ {
			next, err := X25519(k, u)
			if err != nil {
				t.Fatalf("%s: iteration %d: %v", v.Name, i+1, err)
			}
			u, k = k, next
		}
		if want := hex32(t, v.Name, v.Out); k != want {
			t.Errorf("%s: got %x, want %x", v.Name, k, want)
		}
	}

	for _, v := range f.DH {
		a := hex32(t, v.Name, v.AlicePrivate)
		b := hex32(t, v.Name, v.BobPrivate)
		wantA := hex32(t, v.Name, v.AlicePublic)
		wantB := hex32(t, v.Name, v.BobPublic)
		wantK := hex32(t, v.Name, v.Shared)
		if got := PublicKey(a); got != wantA {
			t.Errorf("%s: Alice public key: got %x, want %x", v.Name, got, wantA)
		}
		if got := PublicKey(b); got != wantB {
			t.Errorf("%s: Bob public key: got %x, want %x", v.Name, got, wantB)
		}
		if got, err := X25519(a, wantB); err != nil || got != wantK {
			t.Errorf("%s: Alice shared secret: got %x, %v; want %x", v.Name, got, err, wantK)
		}
		if got, err := X25519(b, wantA); err != nil || got != wantK {
			t.Errorf("%s: Bob shared secret: got %x, %v; want %x", v.Name, got, err, wantK)
		}
	}
}

type wycheproofXDH struct {
	Algorithm     string
	NumberOfTests int
	TestGroups    []struct {
		Curve string
		Tests []struct {
			TcID    int `json:"tcId"`
			Comment string
			Flags   []string
			Public  string
			Private string
			Shared  string
			Result  string
		}
	}
}

func TestCritWycheproofX25519(t *testing.T) {
	var f wycheproofXDH
	readJSON(t, filepath.Join("testdata", "wycheproof", "x25519_test.json"), &f)

	zero := make([]byte, 32)
	ran := 0
	for _, g := range f.TestGroups {
		if g.Curve != "curve25519" {
			t.Fatalf("unexpected curve %q", g.Curve)
		}
		for _, tc := range g.Tests {
			ran++
			name := fmt.Sprintf("tcId %d (%s)", tc.TcID, tc.Comment)
			priv := hex32(t, name, tc.Private)
			pub := hex32(t, name, tc.Public)
			want, err := hex.DecodeString(tc.Shared)
			if err != nil {
				t.Fatalf("%s: bad shared hex", name)
			}
			got, err := X25519(priv, pub)

			switch tc.Result {
			case "valid":
				if err != nil || !bytes.Equal(got[:], want) {
					t.Errorf("%s: valid: got %x, %v; want %x", name, got, err, want)
				}
			case "acceptable":
				if bytes.Equal(want, zero) {
					if !errors.Is(err, ErrZeroSharedSecret) {
						t.Errorf("%s: acceptable with all-zero secret: got %x, %v; want ErrZeroSharedSecret", name, got, err)
					}
				} else if err != nil || !bytes.Equal(got[:], want) {
					t.Errorf("%s: acceptable: got %x, %v; want %x", name, got, err, want)
				}
			case "invalid":
				if err == nil && bytes.Equal(got[:], want) {
					t.Errorf("%s: invalid vector accepted with the expected output %x", name, got)
				}
			default:
				t.Fatalf("%s: unknown result %q", name, tc.Result)
			}
		}
	}
	if ran != f.NumberOfTests {
		t.Errorf("ran %d tests, file declares %d", ran, f.NumberOfTests)
	}
}

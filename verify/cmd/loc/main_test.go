package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCountLines(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      int
	}{
		{"empty", "", 0},
		{"blank and comments", "\n\n// one\n   // two\n/* three\n four */\n\t\n", 0},
		{"code", "package p\n\nfunc f() {}\n", 2},
		{"code with trailing comment", "package p // the package\nvar x = 1 /* one */\n", 2},
		{"comment before code on a line", "/* c */ package p\n", 1},
		{"code after a block comment ends", "package p\n/* a\nb */ var x = 1\n", 2},
		{"markers inside strings", "package p\nvar s = \"// not a comment\"\nvar r = '/'\n", 3},
		{"raw string over lines", "package p\nvar s = `a\n\n// b\n`\n", 4},
		{"no final newline", "package p\nvar x = 1", 2},
	} {
		if got := countLines([]byte(c.src)); got != c.want {
			t.Errorf("%s: countLines = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestCountTree(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	three := "package p\n\n// doc\nvar a = 1\nvar b = 2\n"
	write("internal/x/x.go", three)
	write("cmd/c/main.go", three)
	write("internal/x/x_test.go", three)
	write("sim/s.go", three)
	write("verify/v/v_test.go", three)
	write("verify/v/notes.txt", three)
	write("docs/d.go", three) // outside the counted directories
	tot, err := countTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if want := (totals{product: 6, support: 6, productTests: 3}); tot != want {
		t.Fatalf("countTree = %+v, want %+v", tot, want)
	}
}

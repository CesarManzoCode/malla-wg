// Command loc is criterion 30 of the contract §7: it counts Go lines as
// §2.3 says (non-blank lines that are not only comment) and exits with 0
// only if support has fewer lines than product.
//
//   - product: .go files that are not _test.go under internal/ and cmd/;
//
//   - support: every .go file, tests included, under sim/ and verify/;
//
//   - product tests: _test.go files under internal/ and cmd/, which count
//     on neither side and are reported apart.
//
//     go run ./verify/cmd/loc [-root dir]
package main

import (
	"flag"
	"fmt"
	"go/scanner"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// totals are the three counts of §2.3.
type totals struct {
	product, support, productTests int
}

// budget is the method's reference share of support over product; it is
// reported, not enforced (§2.3).
const budget = 15

func main() {
	root := flag.String("root", ".", "module root")
	flag.Parse()
	tot, err := countTree(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "loc:", err)
		os.Exit(2)
	}
	fmt.Printf("product %d\n", tot.product)
	fmt.Printf("support %d\n", tot.support)
	fmt.Printf("product-tests %d\n", tot.productTests)
	if tot.product == 0 {
		fmt.Println("support/product n/a (no product lines)")
		os.Exit(1)
	}
	fmt.Printf("support/product %.1f%% (reference budget %d%%, not a gate)\n", 100*float64(tot.support)/float64(tot.product), budget)
	if tot.support >= tot.product {
		fmt.Println("loc: support is not smaller than product")
		os.Exit(1)
	}
}

// countTree counts the .go files of internal/, cmd/, sim/ and verify/
// under root. A missing directory counts as empty.
func countTree(root string) (totals, error) {
	var tot totals
	for _, top := range []string{"internal", "cmd", "sim", "verify"} {
		dir := filepath.Join(root, top)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			n := countLines(src)
			switch test := strings.HasSuffix(path, "_test.go"); {
			case top == "sim" || top == "verify":
				tot.support += n
			case test:
				tot.productTests += n
			default:
				tot.product += n
			}
			return nil
		})
		if err != nil {
			return totals{}, err
		}
	}
	return tot, nil
}

// countLines returns how many lines of Go source src have something
// other than blanks and comments. It uses the Go scanner, so comment
// markers inside strings do not count as comments; a token that spans
// lines (a raw string, say) counts each of its non-blank lines.
func countLines(src []byte) int {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, src, func(token.Position, string) {}, 0)
	lines := strings.Split(string(src), "\n")
	code := make(map[int]bool)
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.SEMICOLON && lit == "\n" {
			// Inserted at a line end, not written.
			continue
		}
		first := file.Line(pos)
		last := first + strings.Count(lit, "\n")
		for l := first; l <= last && l <= len(lines); l++ {
			if strings.TrimSpace(lines[l-1]) != "" {
				code[l] = true
			}
		}
	}
	return len(code)
}

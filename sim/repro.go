package sim

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// seedValue is the -sim.seed flag; set records that it was given.
type seedValue struct {
	n   uint64
	set bool
}

func (v *seedValue) String() string { return strconv.FormatUint(v.n, 10) }

func (v *seedValue) Set(s string) error {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return err
	}
	v.n, v.set = n, true
	return nil
}

var seedFlag seedValue

func init() {
	flag.Var(&seedFlag, "sim.seed", "run simulator tests with only this seed")
}

// SeedFlag returns the value of -sim.seed and whether it was given.
func SeedFlag() (uint64, bool) { return seedFlag.n, seedFlag.set }

// Seeds returns the seeds from to to inclusive, or only -sim.seed if it was
// given.
func Seeds(from, to uint64) []uint64 {
	if n, ok := SeedFlag(); ok {
		return []uint64{n}
	}
	var seeds []uint64
	for n := from; n <= to; n++ {
		seeds = append(seeds, n)
	}
	return seeds
}

// Seed returns -sim.seed if it was given and def otherwise.
func Seed(def uint64) uint64 {
	if n, ok := SeedFlag(); ok {
		return n
	}
	return def
}

// Fatal fails t with the message followed by the lines
//
//	seed=<n>
//	repro: go test ./<pkg> -run '^<Test>$' -args -sim.seed=<n>
//
// of the contract §5. The test must honour -sim.seed (Seeds or Seed) for
// the line to repeat the failure.
func Fatal(t testing.TB, seed uint64, format string, args ...any) {
	t.Helper()
	t.Fatalf("%s\nseed=%d\nrepro: %s", fmt.Sprintf(format, args...), seed, ReproCommand(t, seed))
}

// ReproCommand returns the command that repeats t with seed.
func ReproCommand(t testing.TB, seed uint64) string {
	name, _, _ := strings.Cut(t.Name(), "/")
	return fmt.Sprintf("go test %s -run '^%s$' -args -sim.seed=%d", packageDir(), name, seed)
}

// packageDir returns the directory of the running test relative to the
// module root, as ./<pkg>. go test runs a test in its package directory.
func packageDir() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	root, err := ModuleRoot(wd)
	if err != nil {
		return "."
	}
	rel, err := filepath.Rel(root, wd)
	if err != nil || rel == "." {
		return "."
	}
	return "./" + filepath.ToSlash(rel)
}

// ModuleRoot returns the nearest directory at or above dir with a go.mod.
func ModuleRoot(dir string) (string, error) {
	for d := dir; ; {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		up := filepath.Dir(d)
		if up == d {
			return "", fmt.Errorf("sim: no go.mod above %s", dir)
		}
		d = up
	}
}

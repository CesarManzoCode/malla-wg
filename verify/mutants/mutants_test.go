package mutants

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/CesarManzoCode/malla-wg/sim"
)

// event is one line of `go test -json` (cmd/test2json).
type event struct {
	Action string
	Test   string
	Output string
}

// verdict is what a mutated verifier did: whether its top-level test
// ran and failed, and everything it and its subtests printed.
type verdict struct {
	ran, failed bool
	output      string
}

// runMutated runs `go test -tags tag -json -count=1 -run '^test$' pkg`
// from the module root and collects what test did. The go tool must exit
// with a failure; a build error shows up as a test that never ran.
func runMutated(t *testing.T, tag, pkg, test string, timeout time.Duration) verdict {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go tool not found: %v", err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := sim.ModuleRoot(wd)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), timeout+time.Minute)
	defer cancel()
	args := []string{"test", "-tags", tag, "-json", "-count=1", "-timeout", timeout.String(), "-run", "^" + test + "$", pkg}
	cmd := exec.CommandContext(ctx, goBin, args...)
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("go %s: want a failing exit, got %v\n%s%s", strings.Join(args, " "), err, out, stderr.Bytes())
	}
	var v verdict
	var text strings.Builder
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	for sc.Scan() {
		var e event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		if e.Test != test && !strings.HasPrefix(e.Test, test+"/") {
			continue
		}
		text.WriteString(e.Output)
		if e.Test == test {
			switch e.Action {
			case "run":
				v.ran = true
			case "fail":
				v.failed = true
			}
		}
	}
	v.output = text.String()
	if !v.ran {
		t.Fatalf("go %s: %s never ran (build failure?)\n%s%s", strings.Join(args, " "), test, out, stderr.Bytes())
	}
	return v
}

// requireCaught fails unless the mutated verifier failed and its output
// names the violated property.
func requireCaught(t *testing.T, tag, test string, v verdict, property string) {
	t.Helper()
	if !v.failed {
		t.Fatalf("with -tags %s, %s did not fail: the mutant survived\n%s", tag, test, v.output)
	}
	if !strings.Contains(v.output, property) {
		t.Fatalf("with -tags %s, %s failed without %q in its output\n%s", tag, test, property, v.output)
	}
	t.Logf("with -tags %s, %s failed with %q", tag, test, property)
}

// TestCritMutantAntiReplay is criterion 27: with mutant_noreplay the
// replay filter accepts every counter, and TestCritAntiReplayProperty
// must fail naming the anti-replay property.
func TestCritMutantAntiReplay(t *testing.T) {
	const tag, test = "mutant_noreplay", "TestCritAntiReplayProperty"
	v := runMutated(t, tag, "./internal/noise", test, 5*time.Minute)
	requireCaught(t, tag, test, v, "property anti-replay violated")
}

// TestCritMutantRekey is criterion 28: with mutant_norekey the device
// never rekeys and never rejects an old session, and TestCritRekeyTimers
// must fail naming the rekey property.
func TestCritMutantRekey(t *testing.T) {
	const tag, test = "mutant_norekey", "TestCritRekeyTimers"
	v := runMutated(t, tag, "./internal/device", test, 5*time.Minute)
	requireCaught(t, tag, test, v, "property rekey violated")
}

// differingCell matches a cell TestCritSimMatrix reports as differing
// from the theory, with the theory saying direct.
var differingCell = regexp.MustCompile(`(?m)^\s*(pair|hairpin|cgnat|cgnat_same) (\S+): theory direct, observed relay`)

// TestCritMutantHolePunch is criterion 29: with mutant_nopunch only the
// node of smaller key sends pings, and TestCritSimMatrix must fail naming
// the nat-matrix property and at least one cell that matrix/theory.json
// gives as direct. It runs the whole simulated matrix, so like
// TestCritSimMatrix it is skipped with -short.
func TestCritMutantHolePunch(t *testing.T) {
	if testing.Short() {
		t.Skip("long: runs TestCritSimMatrix, 185 cells with 8 seeds each")
	}
	const tag, test = "mutant_nopunch", "TestCritSimMatrix"
	v := runMutated(t, tag, "./verify/matrix", test, 60*time.Minute)
	requireCaught(t, tag, test, v, "property nat-matrix violated")
	theory := loadTheory(t)
	var direct []string
	for _, m := range differingCell.FindAllStringSubmatch(v.output, -1) {
		if theory[m[1]][m[2]] == "direct" {
			direct = append(direct, m[1]+" "+m[2])
		}
	}
	if len(direct) == 0 {
		t.Fatalf("with -tags %s, %s failed without naming a cell that theory.json gives as direct\n%s", tag, test, v.output)
	}
	t.Logf("%d cells the theory gives as direct ended on relay, first %s", len(direct), direct[0])
}

// loadTheory reads matrix/theory.json (contract §4.3) as group → cell →
// result.
func loadTheory(t *testing.T) map[string]map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../../matrix/theory.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Groups map[string]map[string]string `json:"groups"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("theory.json: %v", err)
	}
	return file.Groups
}

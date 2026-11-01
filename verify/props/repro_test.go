package props

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/CesarManzoCode/malla-wg/sim"
)

const forceFailEnv = "MALLA_FORCE_FAIL"

// TestForcedFailure fails on purpose when MALLA_FORCE_FAIL=1: it runs the
// crossed-handshake scenario of -sim.seed (1 by default), prints the
// SHA-256 of its event log and fails with the seed and the repro line.
func TestForcedFailure(t *testing.T) {
	if os.Getenv(forceFailEnv) != "1" {
		t.Skip(forceFailEnv + "=1 not set")
	}
	seed := sim.Seed(1)
	r := crossScenario(t, seed)
	sim.Fatal(t, seed, "forced failure (%s=1)\nlog-sha256=%x", forceFailEnv, sha256.Sum256(r.log))
}

// TestCritFailureRepro is criterion 26: the repro line printed by a failing
// simulator test, run as is, fails again with the same seed and the same
// event log.
func TestCritFailureRepro(t *testing.T) {
	const seed = 11
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
	env := append(os.Environ(), forceFailEnv+"=1")

	first := runFailing(t, root, env, goBin, "test", "./verify/props", "-count=1",
		"-run", "^TestForcedFailure$", "-args", fmt.Sprintf("-sim.seed=%d", seed))
	if first.seed != fmt.Sprint(seed) {
		t.Fatalf("first run printed seed=%q, want %d", first.seed, seed)
	}
	argv, err := splitShell(first.repro)
	if err != nil || len(argv) < 2 || argv[0] != "go" {
		t.Fatalf("repro line %q is not a go command (%v)", first.repro, err)
	}
	second := runFailing(t, root, env, goBin, argv[1:]...)
	if second.seed != first.seed || second.logSum != first.logSum || second.repro != first.repro {
		t.Fatalf("repro run differs: first seed=%s log-sha256=%s repro %q, second seed=%s log-sha256=%s repro %q",
			first.seed, first.logSum, first.repro, second.seed, second.logSum, second.repro)
	}
}

type failure struct{ seed, repro, logSum string }

// runFailing runs the go tool in dir and requires that it fails and prints
// the seed, the repro line and the log digest.
func runFailing(t *testing.T, dir string, env []string, goBin string, args ...string) failure {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, goBin, args...)
	cmd.Dir, cmd.Env = dir, env
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("go %s: want a failing exit, got %v\n%s", strings.Join(args, " "), err, out)
	}
	var f failure
	for line := range strings.Lines(string(out)) {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "seed="):
			f.seed = strings.TrimPrefix(line, "seed=")
		case strings.HasPrefix(line, "repro: "):
			f.repro = strings.TrimPrefix(line, "repro: ")
		case strings.HasPrefix(line, "log-sha256="):
			f.logSum = strings.TrimPrefix(line, "log-sha256=")
		}
	}
	if f.seed == "" || f.repro == "" || f.logSum == "" || !strings.Contains(string(out), "--- FAIL: TestForcedFailure") {
		t.Fatalf("go %s: output lacks the forced failure, seed, repro line or log digest:\n%s", strings.Join(args, " "), out)
	}
	return f
}

// splitShell splits a command line on spaces, honouring single quotes, the
// only quoting the repro line uses.
func splitShell(line string) ([]string, error) {
	var args []string
	var cur strings.Builder
	inWord, quoted := false, false
	for _, c := range line {
		switch {
		case c == '\'':
			quoted, inWord = !quoted, true
		case c == ' ' && !quoted:
			if inWord {
				args = append(args, cur.String())
				cur.Reset()
				inWord = false
			}
		case c == '"' || c == '\\':
			return nil, fmt.Errorf("unsupported quoting %q", c)
		default:
			cur.WriteRune(c)
			inWord = true
		}
	}
	if quoted {
		return nil, errors.New("unterminated quote")
	}
	if inWord {
		args = append(args, cur.String())
	}
	return args, nil
}

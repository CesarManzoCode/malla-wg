// Command critrun runs `go test -json` with its arguments and turns the
// result into the exit codes of the contract §7: 0 if every test passed,
// 77 if the only tests not passed are skips whose message starts with
// "needs-privilege:", and 1 otherwise. It prints one line
// "<Test> pass|skip|fail" per top-level test.
//
//	go run ./verify/critrun -run '^TestCrit' ./verify/e2e
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// event is one line of `go test -json` (cmd/test2json).
type event struct {
	Action  string
	Package string
	Test    string
	Output  string
}

// privilegeSkip matches the message of t.Skip("needs-privilege: …"), with
// or without the "file.go:N: " prefix the testing package adds.
var privilegeSkip = regexp.MustCompile(`^(\S+:\d+: )?needs-privilege:`)

type result struct {
	name      string
	action    string
	privilege bool // its output has a needs-privilege skip message
}

// summarize reads a `go test -json` stream, prints one line per top-level
// test to w and returns the exit code. A package that fails without a
// failing test (a build error, a panic outside tests) and a run without
// any test are failures too.
func summarize(r io.Reader, w io.Writer) int {
	results := map[string]*result{}
	var order []string
	pkgFailed, failed, otherSkip, privSkip := false, 0, 0, 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var e event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			// Build errors and other text reach stdout outside JSON.
			fmt.Fprintln(w, sc.Text())
			continue
		}
		if e.Test == "" {
			if e.Action == "fail" {
				pkgFailed = true
			}
			continue
		}
		if strings.Contains(e.Test, "/") {
			continue
		}
		key := e.Package + "\x00" + e.Test
		res := results[key]
		if res == nil {
			res = &result{name: e.Test}
			results[key] = res
			order = append(order, key)
		}
		switch e.Action {
		case "output":
			if privilegeSkip.MatchString(strings.TrimSpace(e.Output)) {
				res.privilege = true
			}
		case "pass", "fail", "skip":
			res.action = e.Action
			fmt.Fprintf(w, "%s %s\n", e.Test, e.Action)
			switch {
			case e.Action == "fail":
				failed++
			case e.Action == "skip" && res.privilege:
				privSkip++
			case e.Action == "skip":
				otherSkip++
			}
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(w, "critrun: reading go test output: %v\n", err)
		return 1
	}
	for _, key := range order {
		if res := results[key]; res.action == "" {
			fmt.Fprintf(w, "%s fail\n", res.name) // started and never finished
			failed++
		}
	}
	switch {
	case len(order) == 0: // a test that started and never finished ran
		fmt.Fprintln(w, "critrun: no tests ran")
		return 1
	case failed > 0 || otherSkip > 0 || pkgFailed:
		return 1
	case privSkip > 0:
		return 77
	}
	return 0
}

func main() {
	cmd := exec.Command("go", append([]string{"test", "-json"}, os.Args[1:]...)...)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "critrun:", err)
		os.Exit(1)
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "critrun:", err)
		os.Exit(1)
	}
	code := summarize(stdout, os.Stdout)
	if err := cmd.Wait(); err != nil && code != 1 {
		// go test failed in a way the stream did not show; a run whose
		// only problems are privilege skips still exits 0 from go test.
		fmt.Fprintln(os.Stderr, "critrun: go test:", err)
		code = 1
	}
	os.Exit(code)
}

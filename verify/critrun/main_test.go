package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// stream builds a synthetic `go test -json` stream from events.
func stream(t *testing.T, events ...event) string {
	t.Helper()
	var b strings.Builder
	for _, e := range events {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.String()
}

const pkg = "example.com/p"

func run(name string) event { return event{Action: "run", Package: pkg, Test: name} }
func out(name, text string) event {
	return event{Action: "output", Package: pkg, Test: name, Output: text}
}
func end(name, action string) event { return event{Action: action, Package: pkg, Test: name} }

func TestSummarize(t *testing.T) {
	privSkip := []event{
		run("TestCritNet"),
		out("TestCritNet", "=== RUN   TestCritNet\n"),
		out("TestCritNet", "    netns.go:58: needs-privilege: cannot create user and network namespaces\n"),
		out("TestCritNet", "--- SKIP: TestCritNet (0.00s)\n"),
		end("TestCritNet", "skip"),
	}
	pass := []event{run("TestA"), run("TestA/sub"), end("TestA/sub", "pass"), end("TestA", "pass")}
	cases := []struct {
		name   string
		events []event
		code   int
		lines  string
	}{
		{"all pass", append(pass, end("", "pass")), 0, "TestA pass\n"},
		{"privilege skip only", append(append(pass, privSkip...), end("", "pass")), 77,
			"TestA pass\nTestCritNet skip\n"},
		{"plain skip", []event{run("TestB"), out("TestB", "    b_test.go:9: skipping in short mode\n"),
			end("TestB", "skip")}, 1, "TestB skip\n"},
		{"failure beside a privilege skip", append(append([]event{run("TestC"), end("TestC", "fail")}, privSkip...),
			end("", "fail")), 1, "TestC fail\nTestCritNet skip\n"},
		{"subtest failure only counts through its parent", []event{run("TestD"), run("TestD/x"),
			end("TestD/x", "fail"), end("TestD", "fail")}, 1, "TestD fail\n"},
		{"build failure", []event{end("", "fail")}, 1, "critrun: no tests ran\n"},
		{"package fails after passing tests", append(pass, end("", "fail")), 1, "TestA pass\n"},
		{"test never finished", []event{run("TestE")}, 1, "TestE fail\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var w bytes.Buffer
			if code := summarize(strings.NewReader(stream(t, c.events...)), &w); code != c.code {
				t.Errorf("exit code %d, want %d; output:\n%s", code, c.code, w.String())
			}
			if w.String() != c.lines {
				t.Errorf("output %q, want %q", w.String(), c.lines)
			}
		})
	}
}

func TestPrivilegeSkipMessage(t *testing.T) {
	for line, want := range map[string]bool{
		"netns.go:58: needs-privilege: no userns": true,
		"needs-privilege: no userns":              true,
		"x_test.go:3: skipping: needs-privilege:": false,
		"needs privilege":                         false,
	} {
		if got := privilegeSkip.MatchString(line); got != want {
			t.Errorf("%q: got %v, want %v", line, got, want)
		}
	}
}

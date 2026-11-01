// Command deps is criterion 31 of the contract §7: it lists the modules
// that really enter the build and the tests (`go list -deps -test -json
// ./...`), finds the license file of each in its module directory and
// classifies it. It exits with 1 if some license is missing or not one
// of MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, ISC or MPL-2.0, or if
// some module is the SDK of a paid API.
//
//	go run ./verify/cmd/deps
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// pkg is the part of a `go list -json` package that matters here.
type pkg struct {
	ImportPath string
	Standard   bool
	Module     *module
}

type module struct {
	Path    string
	Version string
	Dir     string
	Main    bool
	Replace *module
}

// paidSDKs are module path prefixes of SDKs for paid APIs: language
// models and cloud services that bill per call. The project must build
// and test at zero cost (criterion 31), so none may enter.
var paidSDKs = []string{
	"github.com/anthropics/",
	"github.com/openai/",
	"github.com/sashabaranov/go-openai",
	"google.golang.org/genai",
	"github.com/google/generative-ai-go",
	"cloud.google.com/go/",
	"github.com/aws/aws-sdk-go",
	"github.com/Azure/azure-sdk-for-go",
	"github.com/cohere-ai/",
	"github.com/mistralai/",
	"github.com/stripe/stripe-go",
	"github.com/twilio/twilio-go",
}

func main() {
	cmd := exec.Command("go", "list", "-deps", "-test", "-json", "./...")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "deps: go list:", err)
		os.Exit(2)
	}
	mods, err := modules(bytes.NewReader(out))
	if err != nil {
		fmt.Fprintln(os.Stderr, "deps:", err)
		os.Exit(2)
	}
	bad := 0
	for _, m := range mods {
		license, file := "", "-"
		path, err := findLicense(m.Dir)
		if err == nil {
			file = filepath.Base(path)
			var text []byte
			if text, err = os.ReadFile(path); err == nil {
				license = classify(string(text))
			}
		}
		problem := ""
		switch {
		case err != nil:
			problem = "no license file: " + err.Error()
		case license == "":
			problem = "license not recognized"
		}
		if isPaidSDK(m.Path) {
			problem = strings.TrimPrefix(problem+"; paid API SDK", "; ")
		}
		if license == "" {
			license = "unknown"
		}
		fmt.Printf("%s %s %s %s", m.Path, m.Version, license, file)
		if problem != "" {
			bad++
			fmt.Printf(" FAIL: %s", problem)
		}
		fmt.Println()
	}
	fmt.Printf("deps: %d modules, %d problems\n", len(mods), bad)
	if bad > 0 {
		os.Exit(1)
	}
}

// modules decodes a `go list -json` stream and returns the modules, other
// than the main one, that provide some package, sorted by path. A
// replaced module is reported with the replacement's directory.
func modules(r io.Reader) ([]module, error) {
	seen := make(map[string]module)
	dec := json.NewDecoder(r)
	for {
		var p pkg
		err := dec.Decode(&p)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("go list output: %w", err)
		}
		if p.Standard || p.Module == nil || p.Module.Main {
			continue
		}
		m := *p.Module
		if m.Replace != nil {
			m.Dir = m.Replace.Dir
			if m.Replace.Version != "" {
				m.Version = m.Replace.Version
			}
		}
		seen[m.Path] = m
	}
	out := make([]module, 0, len(seen))
	for _, m := range seen {
		out = append(out, m)
	}
	slices.SortFunc(out, func(a, b module) int { return strings.Compare(a.Path, b.Path) })
	return out, nil
}

// licenseName matches the usual names of a license file.
var licenseName = regexp.MustCompile(`(?i)^(licen[cs]e|copying)([.-].*)?$`)

// findLicense returns the license file at the top of a module directory;
// with several, the shortest name (LICENSE before LICENSE-THIRD-PARTY).
func findLicense(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("module has no directory (not downloaded?)")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	best := ""
	for _, e := range entries {
		n := e.Name()
		if e.Type().IsRegular() && licenseName.MatchString(n) && (best == "" || len(n) < len(best) || len(n) == len(best) && n < best) {
			best = n
		}
	}
	if best == "" {
		return "", fmt.Errorf("none in %s", dir)
	}
	return filepath.Join(dir, best), nil
}

// classify names the license of a license text by phrases of its
// canonical wording, or returns "" if it is none of the accepted ones.
// The text is lowercased and its whitespace and markdown emphasis
// folded, so line wrapping does not matter.
func classify(text string) string {
	t := strings.ToLower(text)
	t = strings.NewReplacer("*", " ", "#", " ", " ", " ").Replace(t)
	t = strings.Join(strings.Fields(t), " ")
	has := func(phrases ...string) bool {
		for _, p := range phrases {
			if !strings.Contains(t, p) {
				return false
			}
		}
		return true
	}
	switch {
	case has("apache license", "version 2.0"):
		return "Apache-2.0"
	case has("mozilla public license", "version 2.0"):
		return "MPL-2.0"
	case has("redistribution and use in source and binary forms", "redistributions of source code must retain"):
		if strings.Contains(t, "neither the name") || strings.Contains(t, "may be used to endorse or promote products") {
			return "BSD-3-Clause"
		}
		return "BSD-2-Clause"
	case has("permission to use, copy, modify, and") && has("distribute this software for any purpose with or without fee is hereby granted"):
		return "ISC"
	case has("permission is hereby granted, free of charge, to any person obtaining a copy", "the above copyright notice and this permission notice shall be included"):
		return "MIT"
	}
	return ""
}

// isPaidSDK reports whether a module path is one of paidSDKs.
func isPaidSDK(path string) bool {
	for _, p := range paidSDKs {
		if path == strings.TrimSuffix(p, "/") || strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

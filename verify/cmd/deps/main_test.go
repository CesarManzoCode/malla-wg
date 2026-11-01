package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Opening lines of the accepted licenses, with the wrapping and markup
// their files use in the wild.
const (
	mitText = `# MIT License

Copyright (C) 2018 Someone

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies.

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.`

	bsd2Text = `Copyright (c) 2020 Someone. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation.`

	bsd3Text = bsd2Text + `
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.`

	apacheText = `
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/`

	iscText = `ISC License

Copyright (c) 2020 Someone

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.`

	mplText = `Mozilla Public License Version 2.0
==================================

1. Definitions`

	gplText = `                    GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007`
)

func TestClassify(t *testing.T) {
	for _, c := range []struct{ name, text, want string }{
		{"MIT", mitText, "MIT"},
		{"MIT with CRLF", strings.ReplaceAll(mitText, "\n", "\r\n"), "MIT"},
		{"BSD-2-Clause", bsd2Text, "BSD-2-Clause"},
		{"BSD-3-Clause", bsd3Text, "BSD-3-Clause"},
		{"Apache-2.0", apacheText, "Apache-2.0"},
		{"ISC", iscText, "ISC"},
		{"ISC without or", strings.Replace(iscText, "and/or", "and", 1), "ISC"},
		{"MPL-2.0", mplText, "MPL-2.0"},
		{"GPL is not accepted", gplText, ""},
		{"empty", "", ""},
		{"MIT header without its text", "MIT License\nCopyright 2020", ""},
	} {
		if got := classify(c.text); got != c.want {
			t.Errorf("%s: classify = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestFindLicense(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"LICENSE-THIRD-PARTY", "LICENSE.md", "README.md", "licenses.go"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(mitText), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "LICENSE"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := findLicense(dir)
	if err != nil || filepath.Base(got) != "LICENSE.md" {
		t.Fatalf("findLicense = %q, %v; want LICENSE.md", got, err)
	}
	empty := t.TempDir()
	if _, err := findLicense(empty); err == nil {
		t.Fatal("findLicense found a license in an empty directory")
	}
	if _, err := findLicense(""); err == nil {
		t.Fatal("findLicense accepted a module without directory")
	}
}

func TestModules(t *testing.T) {
	stream := `{"ImportPath":"fmt","Standard":true}
{"ImportPath":"example.com/main/x","Module":{"Path":"example.com/main","Main":true,"Dir":"/m"}}
{"ImportPath":"golang.org/x/sys/unix","Module":{"Path":"golang.org/x/sys","Version":"v0.1.0","Dir":"/c/sys"}}
{"ImportPath":"golang.org/x/sys/cpu","Module":{"Path":"golang.org/x/sys","Version":"v0.1.0","Dir":"/c/sys"}}
{"ImportPath":"example.com/a","Module":{"Path":"example.com/a","Version":"v1.0.0","Dir":"/c/a","Replace":{"Path":"../a","Dir":"/r/a"}}}
`
	mods, err := modules(strings.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 2 || mods[0].Path != "example.com/a" || mods[0].Dir != "/r/a" || mods[1].Path != "golang.org/x/sys" {
		t.Fatalf("modules = %+v, want example.com/a from /r/a and golang.org/x/sys", mods)
	}
}

func TestIsPaidSDK(t *testing.T) {
	for path, want := range map[string]bool{
		"github.com/anthropics/anthropic-sdk-go": true,
		"github.com/openai/openai-go":            true,
		"github.com/aws/aws-sdk-go-v2":           true,
		"google.golang.org/genai":                true,
		"golang.zx2c4.com/wireguard":             false,
		"golang.org/x/net":                       false,
		"github.com/google/btree":                false,
	} {
		if got := isPaidSDK(path); got != want {
			t.Errorf("isPaidSDK(%q) = %v, want %v", path, got, want)
		}
	}
}

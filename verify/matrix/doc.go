// Package matrix holds the NAT matrix verifiers of the contract §4 and §7
// (criteria 14 to 18). The theoretical table matrix/theory.json is
// generated from the closed rules of §4.2 by ./gentheory and versioned;
// TestCritTheoryCoverage recomputes those rules on its own and compares.
package matrix

//go:generate go run ./gentheory -o ../../matrix/theory.json

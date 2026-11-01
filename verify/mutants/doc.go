// Package mutants holds criteria 27 to 29 of the contract §7: each test
// builds the product with one mutant build tag (mutant_noreplay,
// mutant_norekey, mutant_nopunch), runs in a subprocess the verifier that
// must catch it, and passes only if that verifier fails naming the
// violated property. Without the tags the product does not change.
package mutants

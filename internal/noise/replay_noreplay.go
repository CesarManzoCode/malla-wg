//go:build mutant_noreplay

package noise

// ValidateCounter of the mutant mutant_noreplay (contract §7, criterion
// 27) accepts every counter, so replays, counters behind the window and
// counters over the limit all pass; TestCritAntiReplayProperty must
// catch it.
func (f *ReplayFilter) ValidateCounter(counter, limit uint64) bool {
	return true
}

package interop

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/device"
)

// fatalRecorder records Fatalf instead of stopping the test, so that
// FloodInvalid's failure of the own node can be checked.
type fatalRecorder struct {
	testing.TB
	fatal string
}

func (r *fatalRecorder) Helper() {}

func (r *fatalRecorder) Fatalf(format string, args ...any) { r.fatal = fmt.Sprintf(format, args...) }

// TestFloodInvalid checks which floods count as an attempt: only one
// under floodDeadline that found the oracle under load. A slow flood is
// an invalid attempt, not a failure, unless the own node rejected the
// oracle's cookie reply.
func TestFloodInvalid(t *testing.T) {
	fast, slow := floodDeadline/2, floodDeadline+time.Millisecond
	cookie := device.Event{Kind: device.EventCookie}
	rejected := device.Event{Kind: device.EventDrop, Reason: device.ReasonCookieReply}
	for _, c := range []struct {
		name   string
		took   time.Duration
		loaded bool
		events []device.Event
		want   []string // substrings of the reason; nil means the flood counts
		fatal  bool
	}{
		{"fast-loaded", fast, true, nil, nil, false},
		{"fast-unloaded", fast, false, nil, []string{"not under load"}, false},
		{"slow-unloaded", slow, false, nil, []string{"not under load", "want under"}, false},
		{"slow-loaded-accepted", slow, true, []device.Event{cookie}, []string{"want under"}, false},
		{"slow-loaded-rejected", slow, true, []device.Event{rejected}, []string{"want under"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := &Own{Events: &Events{}}
			for _, ev := range c.events {
				o.Events.add(ev)
			}
			r := &fatalRecorder{TB: t}
			why := FloodInvalid(r, o, c.took, c.loaded)
			if (why == "") != (c.want == nil) {
				t.Fatalf("reason %q, want counted %v", why, c.want == nil)
			}
			for _, w := range c.want {
				if !strings.Contains(why, w) {
					t.Errorf("reason %q lacks %q", why, w)
				}
			}
			if (r.fatal != "") != c.fatal {
				t.Errorf("failure %q, want failure %v", r.fatal, c.fatal)
			}
		})
	}
}

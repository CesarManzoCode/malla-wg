package noise

import (
	"bytes"
	"encoding/binary"
)

// TimestampSize is the size of a TAI64N label.
const TimestampSize = 12

const (
	// tai64Base is 2^62 + 10: the TAI64 label of the Unix epoch, with the
	// 10 s TAI-UTC offset of 1970 that the kernel and wireguard-go use.
	tai64Base = 0x400000000000000a
	// whitenerMask rounds the nanoseconds down to 2^24 ns, the largest
	// power of two under 1 s / INITIATIONS_PER_SECOND, as the kernel's
	// wg_tai64n_now does, so the timestamp does not leak the precise clock.
	whitenerMask = 1<<24 - 1
)

// Timestamp is a TAI64N label: 8 bytes of big-endian seconds and 4 bytes of
// big-endian nanoseconds.
type Timestamp [TimestampSize]byte

// TAI64N returns the label of wall, in Unix nanoseconds.
func TAI64N(wall int64) Timestamp {
	sec, nsec := wall/1e9, wall%1e9
	if nsec < 0 {
		sec, nsec = sec-1, nsec+1e9
	}
	var t Timestamp
	binary.BigEndian.PutUint64(t[:8], uint64(sec)+tai64Base)
	binary.BigEndian.PutUint32(t[8:], uint32(nsec)&^whitenerMask)
	return t
}

// After reports whether t is strictly later than u. Big-endian labels
// order like the bytes.
func (t Timestamp) After(u Timestamp) bool {
	return bytes.Compare(t[:], u[:]) > 0
}

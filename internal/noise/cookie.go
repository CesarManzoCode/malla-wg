package noise

import (
	"crypto/subtle"
	"encoding/binary"
	"io"
	"net/netip"

	"github.com/CesarManzoCode/malla-wg/internal/blake2s"
	"github.com/CesarManzoCode/malla-wg/internal/chachapoly"
)

// cookieChecker is the receiving side of mac1 and mac2, keyed with the
// local public key.
type cookieChecker struct {
	mac1Key     [KeySize]byte // HASH(LABEL_MAC1 || local public)
	cookieKey   [KeySize]byte // HASH(LABEL_COOKIE || local public)
	secret      [KeySize]byte
	secretBirth int64
	secretSet   bool
}

func (c *cookieChecker) init(public [KeySize]byte) {
	c.mac1Key = hash([]byte(LabelMAC1), public[:])
	c.cookieKey = hash([]byte(LabelCookie), public[:])
}

// cookie returns MAC(secret, source IP || source port), the kernel's
// make_cookie: 4 or 16 address bytes and the port in big-endian. The
// secret is replaced with fresh randomness once it is 120 s old.
func (c *cookieChecker) cookie(src netip.AddrPort, now int64, rnd io.Reader) ([blake2s.MACSize]byte, error) {
	if !c.secretSet || now-c.secretBirth >= cookieSecretMaxAge {
		var s [KeySize]byte
		if _, err := io.ReadFull(rnd, s[:]); err != nil {
			return [blake2s.MACSize]byte{}, err
		}
		c.secret, c.secretBirth, c.secretSet = s, now, true
	}
	in := src.Addr().Unmap().AsSlice()
	in = binary.BigEndian.AppendUint16(in, src.Port())
	return blake2s.MAC(c.secret[:], in), nil
}

// hasMACs reports whether b is a serialized initiation or response, the
// two messages that end in mac1 and mac2.
func hasMACs(b []byte) bool {
	t := MessageType(b)
	return t == TypeInitiation || t == TypeResponse
}

// CheckMAC1 reports whether the serialized initiation or response b carries
// mac1 = MAC(HASH(LABEL_MAC1 || local public), b[:offset of mac1]).
func (l *Local) CheckMAC1(b []byte) bool {
	if !hasMACs(b) {
		return false
	}
	n := len(b)
	mac := blake2s.MAC(l.checker.mac1Key[:], b[:n-macsSize])
	return subtle.ConstantTimeCompare(mac[:], b[n-macsSize:n-16]) == 1
}

// CheckMAC2 reports whether b carries mac2 = MAC(cookie, b[:offset of
// mac2]) for the cookie of src. The caller checks mac1 first; rnd is only
// read when the cookie secret has to be renewed.
func (l *Local) CheckMAC2(b []byte, src netip.AddrPort, now int64, rnd io.Reader) (bool, error) {
	if !hasMACs(b) {
		return false, nil
	}
	cookie, err := l.checker.cookie(src, now, rnd)
	if err != nil {
		return false, err
	}
	n := len(b)
	mac := blake2s.MAC(cookie[:], b[:n-16])
	return subtle.ConstantTimeCompare(mac[:], b[n-16:]) == 1, nil
}

// CreateCookieReply answers the serialized initiation or response b, which
// arrived from src while under load. The cookie is encrypted with
// XChaCha20-Poly1305 under HASH(LABEL_COOKIE || local public), a random
// 24-byte nonce and the mac1 of b as associated data; the receiver index
// is the sender index of b.
func (l *Local) CreateCookieReply(b []byte, src netip.AddrPort, now int64, rnd io.Reader) (*CookieReply, error) {
	if !hasMACs(b) {
		return nil, ErrMessageType
	}
	cookie, err := l.checker.cookie(src, now, rnd)
	if err != nil {
		return nil, err
	}
	r := &CookieReply{Receiver: binary.LittleEndian.Uint32(b[4:8])}
	if _, err := io.ReadFull(rnd, r.Nonce[:]); err != nil {
		return nil, err
	}
	n := len(b)
	out, err := chachapoly.XSeal(nil, l.checker.cookieKey[:], r.Nonce[:], cookie[:], b[n-macsSize:n-16])
	if err != nil {
		return nil, err
	}
	copy(r.Cookie[:], out)
	return r, nil
}

// cookieGenerator is the sending side of mac1 and mac2 towards one peer,
// keyed with the peer's public key.
type cookieGenerator struct {
	mac1Key      [KeySize]byte // HASH(LABEL_MAC1 || peer public)
	cookieKey    [KeySize]byte // HASH(LABEL_COOKIE || peer public)
	cookie       [blake2s.MACSize]byte
	cookieBirth  int64
	cookieValid  bool
	lastMAC1     [blake2s.MACSize]byte
	haveSentMAC1 bool
}

func (g *cookieGenerator) init(public [KeySize]byte) {
	g.mac1Key = hash([]byte(LabelMAC1), public[:])
	g.cookieKey = hash([]byte(LabelCookie), public[:])
}

// addMACs fills mac1 and mac2 of the serialized message b. mac2 is zero
// unless a cookie younger than COOKIE_SECRET_MAX_AGE - COOKIE_SECRET_LATENCY
// (115 s) is known. mac1 is remembered to open the cookie reply it may
// trigger.
func (g *cookieGenerator) addMACs(b []byte, now int64) {
	n := len(b)
	g.lastMAC1 = blake2s.MAC(g.mac1Key[:], b[:n-macsSize])
	g.haveSentMAC1 = true
	copy(b[n-macsSize:n-16], g.lastMAC1[:])
	if g.cookieValid && now-g.cookieBirth < cookieSecretMaxAge-cookieSecretLatency {
		mac2 := blake2s.MAC(g.cookie[:], b[:n-16])
		copy(b[n-16:], mac2[:])
	} else {
		clear(b[n-16:])
	}
}

// ConsumeCookieReply stores the cookie of a reply to the last initiation or
// response sent to p, which the caller finds by r.Receiver. A reply is
// accepted at most once per mac1 sent.
func (p *Peer) ConsumeCookieReply(r *CookieReply, now int64) error {
	g := &p.cookie
	if !g.haveSentMAC1 {
		return ErrNoMAC1Sent
	}
	out, err := chachapoly.XOpen(nil, g.cookieKey[:], r.Nonce[:], r.Cookie[:], g.lastMAC1[:])
	if err != nil {
		return ErrDecrypt
	}
	copy(g.cookie[:], out)
	g.cookieBirth, g.cookieValid, g.haveSentMAC1 = now, true, false
	return nil
}

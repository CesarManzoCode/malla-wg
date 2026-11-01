package noise

import (
	"io"

	"github.com/CesarManzoCode/malla-wg/internal/hkdf"
	"github.com/CesarManzoCode/malla-wg/internal/x25519"
)

type handshakeState uint8

const (
	stateZeroed handshakeState = iota
	stateInitiationCreated
	stateInitiationConsumed
	stateResponseCreated
	stateResponseConsumed
)

// handshake is the in-flight Noise_IKpsk2 state with one peer.
type handshake struct {
	state           handshakeState
	hash, chainKey  [KeySize]byte
	localEphemeral  [KeySize]byte // private key
	remoteEphemeral [KeySize]byte // public key
	localIndex      uint32
	remoteIndex     uint32
}

// Local is the node's static identity. It also answers for the responder
// side of mac1, mac2 and cookie replies, which are keyed with its own
// public key.
type Local struct {
	private, public [KeySize]byte
	// hash0 is the handshake hash after mixing the local public key: the
	// responder's starting point.
	hash0   [KeySize]byte
	checker cookieChecker
}

// NewLocal returns the identity of the X25519 private key.
func NewLocal(private [KeySize]byte) *Local {
	l := &Local{private: private, public: x25519.PublicKey(private)}
	l.hash0 = hash(initialHash[:], l.public[:])
	l.checker.init(l.public)
	return l
}

// PublicKey returns the static public key.
func (l *Local) PublicKey() [KeySize]byte { return l.public }

// Peer is the handshake state with one remote static key.
type Peer struct {
	local        *Local
	remote       [KeySize]byte
	psk          [KeySize]byte
	staticStatic [KeySize]byte // DH(local private, remote public)
	// hash0 is the handshake hash after mixing the remote public key: the
	// initiator's starting point.
	hash0 [KeySize]byte
	hs    handshake

	lastTimestamp  Timestamp
	lastInitiation int64 // now of the last accepted initiation
	accepted       bool  // an initiation from this peer was accepted
	cookie         cookieGenerator
}

// NewPeer returns the state for the peer with static public key remote and
// preshared key psk (all zeros when there is none). It fails if the
// static-static DH is zero, as for a small-order public key.
func (l *Local) NewPeer(remote, psk [KeySize]byte) (*Peer, error) {
	ss, err := x25519.X25519(l.private, remote)
	if err != nil {
		return nil, err
	}
	p := &Peer{local: l, remote: remote, psk: psk, staticStatic: ss}
	p.hash0 = hash(initialHash[:], remote[:])
	p.cookie.init(remote)
	return p, nil
}

// PublicKey returns the peer's static public key.
func (p *Peer) PublicKey() [KeySize]byte { return p.remote }

// CreateInitiation starts a handshake as initiator with sender as the local
// index. now is the monotonic time for the cookie, wall the Unix time in
// nanoseconds for the TAI64N timestamp. mac1 and, if a fresh cookie is
// known, mac2 are filled in.
func (p *Peer) CreateInitiation(rnd io.Reader, now, wall int64, sender uint32) (*Initiation, error) {
	eph, err := GeneratePrivateKey(rnd)
	if err != nil {
		return nil, err
	}
	m := &Initiation{Sender: sender, Ephemeral: x25519.PublicKey(eph)}
	h, ck := p.hash0, initialChainKey

	mixHash(&h, m.Ephemeral[:])
	ck = hkdf.KDF1(ck[:], m.Ephemeral[:])

	es, err := x25519.X25519(eph, p.remote)
	if err != nil {
		return nil, err
	}
	ck, key := hkdf.KDF2(ck[:], es[:])
	seal(m.Static[:], &key, &h, p.local.public[:])
	mixHash(&h, m.Static[:])

	ck, key = hkdf.KDF2(ck[:], p.staticStatic[:])
	ts := TAI64N(wall)
	seal(m.Timestamp[:], &key, &h, ts[:])
	mixHash(&h, m.Timestamp[:])

	p.hs = handshake{
		state:          stateInitiationCreated,
		hash:           h,
		chainKey:       ck,
		localEphemeral: eph,
		localIndex:     sender,
	}
	b, _ := m.MarshalBinary()
	p.cookie.addMACs(b, now)
	copy(m.MAC1[:], b[116:132])
	copy(m.MAC2[:], b[132:148])
	return m, nil
}

// ConsumeInitiation processes an initiation addressed to l. lookup maps
// the decrypted initiator static key to its Peer, or nil if unknown. The
// initiation is rejected if its timestamp is not newer than the last one
// accepted from that peer, or if it arrives less than 1/50 s after it, as
// in the kernel. The caller checks mac1 (and mac2 under load) first.
func (l *Local) ConsumeInitiation(m *Initiation, now int64, lookup func(static [KeySize]byte) *Peer) (*Peer, error) {
	h, ck := l.hash0, initialChainKey

	mixHash(&h, m.Ephemeral[:])
	ck = hkdf.KDF1(ck[:], m.Ephemeral[:])

	es, err := x25519.X25519(l.private, m.Ephemeral)
	if err != nil {
		return nil, err
	}
	ck, key := hkdf.KDF2(ck[:], es[:])
	var static [KeySize]byte
	if err := open(static[:], &key, &h, m.Static[:]); err != nil {
		return nil, err
	}
	mixHash(&h, m.Static[:])

	p := lookup(static)
	if p == nil || p.local != l {
		return nil, ErrUnknownPeer
	}
	ck, key = hkdf.KDF2(ck[:], p.staticStatic[:])
	var ts Timestamp
	if err := open(ts[:], &key, &h, m.Timestamp[:]); err != nil {
		return nil, err
	}
	mixHash(&h, m.Timestamp[:])

	if !ts.After(p.lastTimestamp) {
		return nil, ErrStaleTimestamp
	}
	if p.accepted && now-p.lastInitiation < floodInterval {
		return nil, ErrFlood
	}
	p.lastTimestamp, p.lastInitiation, p.accepted = ts, now, true
	p.hs = handshake{
		state:           stateInitiationConsumed,
		hash:            h,
		chainKey:        ck,
		remoteEphemeral: m.Ephemeral,
		remoteIndex:     m.Sender,
	}
	return p, nil
}

// CreateResponse answers the initiation last consumed from p, with sender
// as the local index.
func (p *Peer) CreateResponse(rnd io.Reader, now int64, sender uint32) (*Response, error) {
	if p.hs.state != stateInitiationConsumed {
		return nil, ErrHandshakeState
	}
	eph, err := GeneratePrivateKey(rnd)
	if err != nil {
		return nil, err
	}
	m := &Response{Sender: sender, Receiver: p.hs.remoteIndex, Ephemeral: x25519.PublicKey(eph)}
	h, ck := p.hs.hash, p.hs.chainKey

	mixHash(&h, m.Ephemeral[:])
	ck = hkdf.KDF1(ck[:], m.Ephemeral[:])
	ee, err := x25519.X25519(eph, p.hs.remoteEphemeral)
	if err != nil {
		return nil, err
	}
	ck = hkdf.KDF1(ck[:], ee[:])
	se, err := x25519.X25519(eph, p.remote)
	if err != nil {
		return nil, err
	}
	ck = hkdf.KDF1(ck[:], se[:])

	ck, tau, key := hkdf.KDF3(ck[:], p.psk[:])
	mixHash(&h, tau[:])
	seal(m.Empty[:], &key, &h, nil)
	mixHash(&h, m.Empty[:])

	p.hs.state = stateResponseCreated
	p.hs.hash, p.hs.chainKey = h, ck
	p.hs.localIndex = sender
	clear(eph[:])

	b, _ := m.MarshalBinary()
	p.cookie.addMACs(b, now)
	copy(m.MAC1[:], b[60:76])
	copy(m.MAC2[:], b[76:92])
	return m, nil
}

// ConsumeResponse processes the response to the initiation p created. The
// caller finds p by m.Receiver and checks mac1 (and mac2 under load) first.
// The handshake state only changes if the response is valid.
func (p *Peer) ConsumeResponse(m *Response) error {
	if p.hs.state != stateInitiationCreated {
		return ErrHandshakeState
	}
	if m.Receiver != p.hs.localIndex {
		return ErrIndex
	}
	h, ck := p.hs.hash, p.hs.chainKey

	mixHash(&h, m.Ephemeral[:])
	ck = hkdf.KDF1(ck[:], m.Ephemeral[:])
	ee, err := x25519.X25519(p.hs.localEphemeral, m.Ephemeral)
	if err != nil {
		return err
	}
	ck = hkdf.KDF1(ck[:], ee[:])
	se, err := x25519.X25519(p.local.private, m.Ephemeral)
	if err != nil {
		return err
	}
	ck = hkdf.KDF1(ck[:], se[:])

	ck, tau, key := hkdf.KDF3(ck[:], p.psk[:])
	mixHash(&h, tau[:])
	if err := open(nil, &key, &h, m.Empty[:]); err != nil {
		return err
	}
	mixHash(&h, m.Empty[:])

	p.hs.state = stateResponseConsumed
	p.hs.hash, p.hs.chainKey = h, ck
	p.hs.remoteEphemeral = m.Ephemeral
	p.hs.remoteIndex = m.Sender
	clear(p.hs.localEphemeral[:])
	return nil
}

// BeginSession derives the transport keypair once the initiator consumed
// the response or the responder created it, and zeroes the handshake:
// (T_send, T_recv) = Kdf2(C, ε) for the initiator, swapped for the
// responder.
func (p *Peer) BeginSession() (*Keypair, error) {
	var initiator bool
	switch p.hs.state {
	case stateResponseConsumed:
		initiator = true
	case stateResponseCreated:
	default:
		return nil, ErrHandshakeState
	}
	t1, t2 := hkdf.KDF2(p.hs.chainKey[:], nil)
	k := &Keypair{
		LocalIndex:  p.hs.localIndex,
		RemoteIndex: p.hs.remoteIndex,
		Initiator:   initiator,
	}
	if initiator {
		k.send, k.recv = t1, t2
	} else {
		k.send, k.recv = t2, t1
	}
	p.hs = handshake{}
	return k, nil
}

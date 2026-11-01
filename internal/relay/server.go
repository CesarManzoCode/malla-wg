package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/CesarManzoCode/malla-wg/internal/coord"
)

// Files of the relay's certificate inside state_dir.
const (
	CertFile = "relay-cert.pem"
	KeyFile  = "relay-key.pem"
)

// ServerConfig configures a Server.
type ServerConfig struct {
	StateDir string
	// CaptureFile, if set, receives every forwarded datagram as a u32
	// big-endian length followed by its bytes, for the tests to examine.
	CaptureFile string
	// Logf, if set, receives one line per connection that breaks the
	// protocol.
	Logf func(format string, args ...any)
}

// Server is the relay over HTTPS: it serializes every frame on Core and
// queues the frames Core decides on the connections' writers.
type Server struct {
	mu      sync.Mutex
	core    *Core
	conns   map[ConnID]*frameConn
	next    ConnID
	capture *os.File
	closed  bool

	cert tls.Certificate
	fp   string
	logf func(string, ...any)
}

// NewServer loads or creates the certificate of cfg.StateDir and opens
// the capture file, truncating it.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.StateDir == "" {
		return nil, errors.New("relay: state_dir is required")
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	s := &Server{core: NewCore(), conns: make(map[ConnID]*frameConn), logf: cfg.Logf}
	if s.logf == nil {
		s.logf = log.Printf
	}
	var err error
	s.cert, s.fp, err = coord.LoadOrCreateCertFiles(filepath.Join(cfg.StateDir, CertFile), filepath.Join(cfg.StateDir, KeyFile), "malla-relay")
	if err != nil {
		return nil, err
	}
	if cfg.CaptureFile != "" {
		if s.capture, err = os.OpenFile(cfg.CaptureFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Fingerprint is the value nodes pin as relay_fingerprint.
func (s *Server) Fingerprint() string { return s.fp }

// Serve answers HTTPS on ln until ctx is done, then closes every
// connection, the upgraded ones included, and the capture file.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	hs := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: handshakeTimeout,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{s.cert}},
		// HTTP/1.1 only: an Upgrade needs a connection to hijack.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	errc := make(chan error, 1)
	go func() { errc <- hs.ServeTLS(ln, "", "") }()
	var err error
	select {
	case <-ctx.Done():
		hs.Close()
		<-errc
	case err = <-errc:
	}
	s.shutdown()
	return err
}

// Handler returns the Upgrade route, without TLS.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+Path, s.upgrade)
	return mux
}

func (s *Server) shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for _, c := range s.conns {
		c.close()
	}
	if s.capture != nil {
		s.capture.Close()
		s.capture = nil
	}
}

// hasToken reports whether the comma-separated header h holds token,
// ignoring case.
func hasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, f := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), token) {
				return true
			}
		}
	}
	return false
}

func (s *Server) upgrade(w http.ResponseWriter, r *http.Request) {
	if !hasToken(r.Header, "Connection", "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), Protocol) {
		w.Header().Set("Upgrade", Protocol)
		http.Error(w, "relay: want Connection: Upgrade and Upgrade: "+Protocol, http.StatusUpgradeRequired)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "relay: connection cannot be upgraded", http.StatusInternalServerError)
		return
	}
	nc, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	nc.SetDeadline(time.Now().Add(writeTimeout))
	brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + Protocol + "\r\n\r\n")
	if err := brw.Flush(); err != nil {
		nc.Close()
		return
	}
	nc.SetDeadline(time.Time{})
	s.serveConn(nc, brw.Reader)
}

// serveConn reads the frames of one upgraded connection until it breaks
// the protocol, goes silent for ReadTimeout or closes.
func (s *Server) serveConn(nc net.Conn, br *bufio.Reader) {
	c := newFrameConn(nc)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		c.close()
		return
	}
	s.next++
	id := s.next
	s.conns[id] = c
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.conns, id)
		s.core.Closed(id)
		s.mu.Unlock()
		c.close()
	}()

	var buf []byte
	for {
		nc.SetReadDeadline(time.Now().Add(ReadTimeout))
		var t Type
		var payload []byte
		var err error
		t, payload, buf, err = ReadFrame(br, buf)
		if err != nil {
			return
		}
		s.mu.Lock()
		res, err := s.core.Handle(id, t, payload)
		if err == nil {
			s.apply(res)
		}
		s.mu.Unlock()
		if err != nil {
			s.logf("relay: %s: %s frame: %v", nc.RemoteAddr(), t, err)
			return
		}
	}
}

// apply carries out one Result; s.mu is held.
func (s *Server) apply(res Result) {
	if res.Forwarded != nil && s.capture != nil {
		rec := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(res.Forwarded)), uint32(len(res.Forwarded)))
		if _, err := s.capture.Write(append(rec, res.Forwarded...)); err != nil {
			s.logf("relay: capture: %v", err)
		}
	}
	for _, o := range res.Out {
		if c := s.conns[o.To]; c != nil {
			c.enqueue(o.Frame)
		}
	}
	for _, id := range res.Close {
		if c := s.conns[id]; c != nil {
			c.close()
		}
	}
}

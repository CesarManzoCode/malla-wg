package coord

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// StateFile is the coordination's persisted state inside state_dir.
const StateFile = "state.json"

// LongPoll is how long GET /v1/netmap waits for a newer version.
const LongPoll = 25 * time.Second

const maxBody = 1 << 20

// ServerConfig configures a Server.
type ServerConfig struct {
	StateDir   string
	AdminToken string
	AuthKeys   []string
	Policy     *Policy // initial policy, from policy_file
	Relay      string
	// LongPoll overrides the long-poll wait; 0 means LongPoll.
	LongPoll time.Duration
	// Logf, if set, receives one line per failed request.
	Logf func(format string, args ...any)
}

// Server is the coordination over HTTPS: it serializes the requests on
// Core, persists the state after every change and wakes the long-polls.
type Server struct {
	mu      sync.Mutex
	core    *Core
	changed chan struct{} // closed and replaced on every change

	stateFile string
	cert      tls.Certificate
	fp        string
	longPoll  time.Duration
	logf      func(string, ...any)
}

// NewServer loads or creates the state and the certificate of
// cfg.StateDir.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.StateDir == "" {
		return nil, errors.New("coord: state_dir is required")
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	s := &Server{
		changed:   make(chan struct{}),
		stateFile: filepath.Join(cfg.StateDir, StateFile),
		longPoll:  cfg.LongPoll,
		logf:      cfg.Logf,
	}
	if s.longPoll <= 0 {
		s.longPoll = LongPoll
	}
	if s.logf == nil {
		s.logf = log.Printf
	}
	saved, err := os.ReadFile(s.stateFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	s.core, err = NewCore(CoreConfig{AuthKeys: cfg.AuthKeys, AdminToken: cfg.AdminToken, Policy: cfg.Policy, Relay: cfg.Relay}, saved)
	if err != nil {
		return nil, err
	}
	if s.cert, s.fp, err = LoadOrCreateCert(cfg.StateDir); err != nil {
		return nil, err
	}
	return s, s.save()
}

// Fingerprint is the value nodes pin as coord_fingerprint.
func (s *Server) Fingerprint() string { return s.fp }

// Serve answers HTTPS on ln until ctx is done, then closes every
// connection, long-polls included, and returns nil.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	hs := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{s.cert}},
	}
	errc := make(chan error, 1)
	go func() { errc <- hs.ServeTLS(ln, "", "") }()
	select {
	case <-ctx.Done():
		hs.Close()
		<-errc
		return nil
	case err := <-errc:
		return err
	}
}

// Handler returns the routes of contract §3.1, without TLS.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/register", s.register)
	mux.HandleFunc("GET /v1/netmap", s.netmap)
	mux.HandleFunc("POST /v1/endpoints", s.endpoints)
	mux.HandleFunc("PUT /v1/admin/policy", s.policy)
	mux.HandleFunc("POST /v1/admin/revoke", s.revoke)
	return mux
}

func (s *Server) save() error {
	b, err := s.core.Marshal()
	if err != nil {
		return err
	}
	return writeFileAtomic(s.stateFile, b, 0o600)
}

// mutate runs fn on Core and, if it succeeds, persists the state and wakes
// the long-polls.
func (s *Server) mutate(fn func(*Core) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(s.core); err != nil {
		return err
	}
	close(s.changed)
	s.changed = make(chan struct{})
	if err := s.save(); err != nil {
		return fmt.Errorf("coord: saving state: %w", err)
	}
	return nil
}

func bearer(r *http.Request) string {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return strings.TrimSpace(tok)
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrBadRequest, err)
	}
	return nil
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	code := http.StatusInternalServerError
	for _, m := range []struct {
		err  error
		code int
	}{
		{ErrBadRequest, http.StatusBadRequest},
		{ErrUnauthorized, http.StatusUnauthorized},
		{ErrForbidden, http.StatusForbidden},
		{ErrNotFound, http.StatusNotFound},
		{ErrConflict, http.StatusConflict},
		{ErrFull, http.StatusServiceUnavailable},
	} {
		if errors.Is(err, m.err) {
			code = m.code
			break
		}
	}
	s.logf("coord: %s %s: %d %v", r.Method, r.URL.Path, code, err)
	http.Error(w, err.Error(), code)
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	var resp RegisterResponse
	err := decode(r, &req)
	if err == nil {
		err = s.mutate(func(c *Core) (err error) {
			resp, err = c.Register(req, rand.Reader)
			return err
		})
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply(w, resp)
}

// netmap answers at once if the map is newer than since, and otherwise
// waits up to the long-poll for a change and answers with the map then.
func (s *Server) netmap(w http.ResponseWriter, r *http.Request) {
	var since uint64
	if v := r.URL.Query().Get("since"); v != "" {
		var err error
		if since, err = strconv.ParseUint(v, 10, 64); err != nil {
			s.fail(w, r, fmt.Errorf("%w: since: %v", ErrBadRequest, err))
			return
		}
	}
	token := bearer(r)
	timeout := time.NewTimer(s.longPoll)
	defer timeout.Stop()
	for {
		s.mu.Lock()
		nm, err := s.core.Netmap(token)
		changed := s.changed
		s.mu.Unlock()
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if nm.Version > since {
			reply(w, nm)
			return
		}
		select {
		case <-changed:
		case <-timeout.C:
			reply(w, nm)
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) endpoints(w http.ResponseWriter, r *http.Request) {
	var req EndpointsRequest
	err := decode(r, &req)
	if err == nil {
		err = s.mutate(func(c *Core) error { return c.SetEndpoints(bearer(r), req.Endpoints) })
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply(w, struct{}{})
}

func (s *Server) policy(w http.ResponseWriter, r *http.Request) {
	var p Policy
	err := decode(r, &p)
	if err == nil {
		err = s.mutate(func(c *Core) error { return c.SetPolicy(bearer(r), p) })
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply(w, struct{}{})
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	var req RevokeRequest
	err := decode(r, &req)
	if err == nil {
		err = s.mutate(func(c *Core) error { return c.Revoke(bearer(r), req.NodeID) })
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply(w, struct{}{})
}

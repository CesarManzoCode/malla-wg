package coord

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Files of the coordination's certificate inside state_dir.
const (
	CertFile = "coord-cert.pem"
	KeyFile  = "coord-key.pem"
)

// Fingerprint is the pinned form of a certificate: the SHA-256 of its DER
// in lowercase hex.
func Fingerprint(der []byte) string {
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

// LoadOrCreateCert loads the certificate of dir, or generates and saves a
// self-signed ECDSA P-256 one on the first start, and returns it with its
// fingerprint.
func LoadOrCreateCert(dir string) (tls.Certificate, string, error) {
	return LoadOrCreateCertFiles(filepath.Join(dir, CertFile), filepath.Join(dir, KeyFile), "malla-coord")
}

// LoadOrCreateCertFiles is LoadOrCreateCert with explicit file paths and
// the certificate's common name; the relay keeps its own pair with it.
func LoadOrCreateCertFiles(certPath, keyPath, commonName string) (tls.Certificate, string, error) {
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return cert, Fingerprint(cert.Certificate[0]), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return tls.Certificate{}, "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(20, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	if err := writeFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0o600); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := writeFileAtomic(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, "", err
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	return cert, Fingerprint(der), nil
}

// PinnedTLSConfig returns a TLS 1.3 client configuration that accepts only
// the certificate whose fingerprint is fp (hex, case and colons ignored).
// The chain and the name are not checked: the pin replaces them.
func PinnedTLSConfig(fp string) (*tls.Config, error) {
	want, err := hex.DecodeString(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(fp)), ":", ""))
	if err != nil || len(want) != sha256.Size {
		return nil, fmt.Errorf("coord: fingerprint %q is not a hex SHA-256", fp)
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("coord: no certificate")
			}
			got := sha256.Sum256(raw[0])
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return fmt.Errorf("coord: certificate fingerprint %x does not match the pinned one", got)
			}
			return nil
		},
	}, nil
}

// writeFileAtomic writes b to a temporary file next to path and renames
// it over path, so a crash never leaves a half-written file.
func writeFileAtomic(path string, b []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

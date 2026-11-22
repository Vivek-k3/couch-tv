// Package atv implements a minimal client for the Android TV Remote Service v2
// protocol (the one used by the Google TV phone app): pairing on port 6467 and
// key injection on port 6466. Protobuf messages are hand-encoded with protowire
// to avoid generated code and keep the binary small.
package atv

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// ---- protobuf helpers -------------------------------------------------------

type msg []byte

func (m msg) varint(num protowire.Number, v uint64) msg {
	m = protowire.AppendTag(m, num, protowire.VarintType)
	return protowire.AppendVarint(m, v)
}

func (m msg) bytes(num protowire.Number, b []byte) msg {
	m = protowire.AppendTag(m, num, protowire.BytesType)
	return protowire.AppendBytes(m, b)
}

func protowireNum(i int) protowire.Number { return protowire.Number(i) }

func (m msg) str(num protowire.Number, s string) msg { return m.bytes(num, []byte(s)) }

// fields decodes one level of a protobuf message into varints and bytes keyed
// by field number (last value wins, which is all we need).
type fields struct {
	v map[protowire.Number]uint64
	b map[protowire.Number][]byte
}

func (f fields) has(n protowire.Number) bool {
	_, a := f.v[n]
	_, b := f.b[n]
	return a || b
}

func parse(b []byte) (fields, error) {
	f := fields{v: map[protowire.Number]uint64{}, b: map[protowire.Number][]byte{}}
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return f, protowire.ParseError(n)
		}
		b = b[n:]
		switch typ {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return f, protowire.ParseError(n)
			}
			f.v[num] = v
			b = b[n:]
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return f, protowire.ParseError(n)
			}
			f.b[num] = v
			b = b[n:]
		default:
			n := protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return f, protowire.ParseError(n)
			}
			b = b[n:]
		}
	}
	return f, nil
}

// ---- framing: varint length prefix -------------------------------------------

func writeFrame(w io.Writer, m []byte) error {
	buf := protowire.AppendVarint(make([]byte, 0, len(m)+4), uint64(len(m)))
	_, err := w.Write(append(buf, m...))
	return err
}

func readFrame(r *bufio.Reader) ([]byte, error) {
	var size uint64
	for shift := 0; ; shift += 7 {
		if shift > 28 {
			return nil, errors.New("atv: frame length too long")
		}
		c, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		size |= uint64(c&0x7f) << shift
		if c < 0x80 {
			break
		}
	}
	if size > 1<<20 {
		return nil, fmt.Errorf("atv: frame too large (%d)", size)
	}
	b := make([]byte, size)
	_, err := io.ReadFull(r, b)
	return b, err
}

// ---- client certificate -------------------------------------------------------

// LoadOrCreateCert returns the persistent client certificate the TV pairs with.
// The protocol's PIN hash uses the RSA modulus/exponent, so it must be RSA.
func LoadOrCreateCert(dir string) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, "atv-cert.pem"), filepath.Join(dir, "atv-key.pem")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return c, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "tvbridge"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(30, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func tlsConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		// Always present our self-signed cert. With plain Certificates, Go
		// silently omits it when the TV advertises acceptable CAs it isn't from.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
		InsecureSkipVerify: true, // TV uses a self-signed cert; trust is established by PIN pairing
	}
}

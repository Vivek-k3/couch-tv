package atv

import (
	"bufio"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// Pairing protocol ("polo") field numbers in OuterMessage.
const (
	fPairingRequest    = 10
	fPairingRequestAck = 11
	fOptions           = 20
	fConfiguration     = 30
	fConfigurationAck  = 31
	fSecret            = 40
	fSecretAck         = 41

	statusOK        = 200
	encodingHex     = 3
	roleInput       = 1
	codeSymbolCount = 6
)

var ErrBadCode = errors.New("atv: pairing code rejected")

// Pairing is an in-progress pairing session. Start shows a code on the TV;
// Finish submits it.
type Pairing struct {
	conn   *tls.Conn
	r      *bufio.Reader
	client *rsa.PublicKey
	server *rsa.PublicKey
}

func outer(payloadField int, payload msg) msg {
	return msg{}.varint(1, 2).varint(2, statusOK).bytes(protowireNum(payloadField), payload)
}

func (p *Pairing) roundTrip(field int, payload msg, want int) (fields, error) {
	if err := writeFrame(p.conn, outer(field, payload)); err != nil {
		return fields{}, err
	}
	b, err := readFrame(p.r)
	if err != nil {
		return fields{}, err
	}
	f, err := parse(b)
	if err != nil {
		return f, err
	}
	if st := f.v[2]; st != statusOK {
		if st == 402 {
			return f, ErrBadCode
		}
		return f, fmt.Errorf("atv: pairing step %d failed with status %d", field, st)
	}
	if want != 0 && !f.has(protowireNum(want)) {
		return f, fmt.Errorf("atv: pairing step %d: unexpected reply", field)
	}
	return f, nil
}

// StartPairing connects to the TV pairing port and makes it display a code.
func StartPairing(host string, cert tls.Certificate, clientName string) (*Pairing, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, "6467"), tlsConfig(cert))
	if err != nil {
		return nil, fmt.Errorf("atv: connect pairing port: %w", err)
	}
	p := &Pairing{conn: conn, r: bufio.NewReader(conn)}
	if pc := conn.ConnectionState().PeerCertificates; len(pc) > 0 {
		p.server, _ = pc[0].PublicKey.(*rsa.PublicKey)
	}
	p.client, _ = cert.Leaf.PublicKey.(*rsa.PublicKey)
	if p.server == nil || p.client == nil {
		conn.Close()
		return nil, errors.New("atv: TV or client certificate is not RSA")
	}
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	encoding := msg{}.varint(1, encodingHex).varint(2, codeSymbolCount)
	steps := []struct {
		field, want int
		payload     msg
	}{
		{fPairingRequest, fPairingRequestAck, msg{}.str(1, "atvremote").str(2, clientName)},
		{fOptions, fOptions, msg{}.bytes(1, encoding).varint(3, roleInput)},
		{fConfiguration, fConfigurationAck, msg{}.bytes(1, encoding).varint(2, roleInput)},
	}
	for _, s := range steps {
		if _, err := p.roundTrip(s.field, s.payload, s.want); err != nil {
			conn.Close()
			return nil, err
		}
	}
	conn.SetDeadline(time.Time{})
	return p, nil
}

// Finish submits the 6 hex character code shown on the TV.
func (p *Pairing) Finish(code string) error {
	defer p.conn.Close()
	code = strings.ToUpper(strings.TrimSpace(code))
	raw, err := hex.DecodeString(code)
	if err != nil || len(raw) != 3 {
		return fmt.Errorf("atv: code must be %d hex characters", codeSymbolCount)
	}
	h := sha256.New()
	h.Write(p.client.N.Bytes())
	h.Write(big.NewInt(int64(p.client.E)).Bytes())
	h.Write(p.server.N.Bytes())
	h.Write(big.NewInt(int64(p.server.E)).Bytes())
	h.Write(raw[1:])
	secret := h.Sum(nil)
	if secret[0] != raw[0] {
		return ErrBadCode // first byte of the code is a checksum of the hash
	}
	p.conn.SetDeadline(time.Now().Add(15 * time.Second))
	_, err = p.roundTrip(fSecret, msg{}.bytes(1, secret), fSecretAck)
	return err
}

// Close abandons the pairing session.
func (p *Pairing) Close() { p.conn.Close() }

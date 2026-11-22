// Package adb is a minimal ADB wire-protocol client: connect to an adbd over
// TCP, authenticate with an RSA key, and run a shell command. The launcher app
// uses it to start the bridge as the shell user via the TV's own adbd.
package adb

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	cmdCNXN = 0x4e584e43
	cmdAUTH = 0x48545541
	cmdOPEN = 0x4e45504f
	cmdOKAY = 0x59414b4f
	cmdCLSE = 0x45534c43
	cmdWRTE = 0x45545257

	authToken     = 1
	authSignature = 2
	authPublicKey = 3

	version = 0x01000001
	maxData = 256 * 1024
)

type packet struct {
	cmd, arg0, arg1 uint32
	data            []byte
}

func writePacket(w io.Writer, p packet) error {
	var sum uint32
	for _, b := range p.data {
		sum += uint32(b)
	}
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], p.cmd)
	binary.LittleEndian.PutUint32(hdr[4:], p.arg0)
	binary.LittleEndian.PutUint32(hdr[8:], p.arg1)
	binary.LittleEndian.PutUint32(hdr[12:], uint32(len(p.data)))
	binary.LittleEndian.PutUint32(hdr[16:], sum)
	binary.LittleEndian.PutUint32(hdr[20:], p.cmd^0xffffffff)
	_, err := w.Write(append(hdr, p.data...))
	return err
}

func readPacket(r io.Reader) (packet, error) {
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return packet{}, err
	}
	p := packet{
		cmd:  binary.LittleEndian.Uint32(hdr[0:]),
		arg0: binary.LittleEndian.Uint32(hdr[4:]),
		arg1: binary.LittleEndian.Uint32(hdr[8:]),
	}
	n := binary.LittleEndian.Uint32(hdr[12:])
	if n > maxData {
		return p, fmt.Errorf("adb: packet too large (%d)", n)
	}
	p.data = make([]byte, n)
	_, err := io.ReadFull(r, p.data)
	return p, err
}

// LoadOrCreateKey loads the RSA key adbd will be asked to trust.
func LoadOrCreateKey(dir string) (*rsa.PrivateKey, error) {
	path := filepath.Join(dir, "adbkey")
	if b, err := os.ReadFile(path); err == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			return x509.ParsePKCS1PrivateKey(blk.Bytes)
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	os.MkdirAll(dir, 0o700)
	err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600)
	return key, err
}

// androidPubKey encodes the key in adbd's RSAPublicKey format, base64 + name.
func androidPubKey(pub *rsa.PublicKey, name string) []byte {
	const words = 64 // 2048-bit
	r32 := new(big.Int).Lsh(big.NewInt(1), 32)
	n0inv := new(big.Int).Mod(pub.N, r32)
	n0inv.ModInverse(n0inv, r32)
	n0inv.Sub(r32, n0inv)
	rr := new(big.Int).Lsh(big.NewInt(1), words*32*2)
	rr.Mod(rr, pub.N)

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint32(words))
	binary.Write(&buf, binary.LittleEndian, uint32(n0inv.Uint64()))
	le := func(x *big.Int) {
		b := x.FillBytes(make([]byte, words*4)) // big-endian
		for i := len(b) - 1; i >= 0; i-- {
			buf.WriteByte(b[i])
		}
	}
	le(pub.N)
	le(rr)
	binary.Write(&buf, binary.LittleEndian, uint32(pub.E))
	out := []byte(base64.StdEncoding.EncodeToString(buf.Bytes()))
	return append(append(out, ' '), append([]byte(name), 0)...)
}

// ErrUnauthorized means the user has not yet accepted the debugging prompt.
var ErrUnauthorized = errors.New("adb: waiting for 'Allow debugging' approval on the TV")

// Shell connects to addr, authenticates, runs cmd and returns its output.
// approval is how long to wait for the user to accept a first-time prompt.
func Shell(addr string, key *rsa.PrivateKey, cmd string, approval time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	if err := writePacket(conn, packet{cmdCNXN, version, maxData, []byte("host::tvbridge\x00")}); err != nil {
		return "", err
	}
	sentSig, sentPub := false, false
	for connected := false; !connected; {
		p, err := readPacket(conn)
		if err != nil {
			if sentPub {
				return "", ErrUnauthorized
			}
			return "", err
		}
		switch {
		case p.cmd == cmdCNXN:
			connected = true
		case p.cmd == cmdAUTH && p.arg0 == authToken && !sentSig:
			sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA1, p.data)
			if err != nil {
				return "", err
			}
			writePacket(conn, packet{cmdAUTH, authSignature, 0, sig})
			sentSig = true
		case p.cmd == cmdAUTH && p.arg0 == authToken && !sentPub:
			writePacket(conn, packet{cmdAUTH, authPublicKey, 0, androidPubKey(&key.PublicKey, "tvbridge@tv")})
			sentPub = true
			conn.SetDeadline(time.Now().Add(approval))
		default:
			return "", fmt.Errorf("adb: unexpected packet %08x during auth", p.cmd)
		}
	}

	conn.SetDeadline(time.Now().Add(30 * time.Second))
	const localID = 1
	if err := writePacket(conn, packet{cmdOPEN, localID, 0, append([]byte("shell:"+cmd), 0)}); err != nil {
		return "", err
	}
	var out bytes.Buffer
	for {
		p, err := readPacket(conn)
		if err != nil {
			return out.String(), err
		}
		switch p.cmd {
		case cmdOKAY:
		case cmdWRTE:
			out.Write(p.data)
			writePacket(conn, packet{cmdOKAY, localID, p.arg0, nil})
		case cmdCLSE:
			writePacket(conn, packet{cmdCLSE, localID, p.arg0, nil})
			return out.String(), nil
		}
	}
}

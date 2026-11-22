package companion

import (
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tadglines/go-pkgs/crypto/srp"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

type recHandler struct {
	mu      sync.Mutex
	pin     chan string
	buttons []string
}

func (h *recHandler) Button(code int, down bool) {
	h.mu.Lock()
	h.buttons = append(h.buttons, fmt.Sprintf("%d:%v", code, down))
	h.mu.Unlock()
}
func (h *recHandler) Touch(int, float64, float64) {}
func (h *recHandler) ShowPin(p string) {
	if p != "" {
		h.pin <- p
	}
}

// testClient plays the iPhone's side of the protocol.
type testClient struct {
	t       *testing.T
	c       net.Conn
	out, in interface {
		Seal(dst, nonce, plaintext, ad []byte) []byte
		Open(dst, nonce, ciphertext, ad []byte) ([]byte, error)
		Overhead() int
	}
	outN, inN uint64
}

func (tc *testClient) send(typ byte, payload []byte) {
	n := len(payload)
	if tc.out != nil {
		n += 16
	}
	hdr := []byte{typ, byte(n >> 16), byte(n >> 8), byte(n)}
	if tc.out != nil {
		nonce := make([]byte, 12)
		binary.LittleEndian.PutUint64(nonce, tc.outN)
		tc.outN++
		payload = tc.out.Seal(nil, nonce, payload, hdr)
	}
	tc.c.Write(append(hdr, payload...))
}

func (tc *testClient) recv() (byte, map[string]any) {
	tc.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(tc.c, hdr); err != nil {
		tc.t.Fatal(err)
	}
	p := make([]byte, int(hdr[1])<<16|int(hdr[2])<<8|int(hdr[3]))
	io.ReadFull(tc.c, p)
	if tc.in != nil {
		nonce := make([]byte, 12)
		binary.LittleEndian.PutUint64(nonce, tc.inN)
		tc.inN++
		var err error
		if p, err = tc.in.Open(nil, nonce, p, hdr); err != nil {
			tc.t.Fatal("client decrypt:", err)
		}
	}
	v, err := opackDecode(p)
	if err != nil {
		tc.t.Fatal(err)
	}
	return hdr[0], asMap(v)
}

func (tc *testClient) pairing(typ byte, items ...tlvItem) map[byte][]byte {
	tc.send(typ, opackEncode(map[string]any{"_pd": tlvEncode(items...), "_pwTy": int64(1)}))
	_, m := tc.recv()
	return tlvDecode(m["_pd"].([]byte))
}

func TestPairSetupVerifyAndSession(t *testing.T) {
	h := &recHandler{pin: make(chan string, 1)}
	s := &Server{Name: "Test TV", DataDir: t.TempDir(), Handler: h}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Run only the TCP part (no mDNS in tests).
	if err := s.load(); err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go (&conn{s: s, c: c}).serve()
		}
	}()
	_ = ctx

	ctrlPub, ctrlPriv, _ := ed25519.GenerateKey(nil)
	ctrlID := []byte("C0FFEE00-TEST-IPHONE")

	// --- pair-setup ---
	c1, _ := net.Dial("tcp", ln.Addr().String())
	tc := &testClient{t: t, c: c1}
	m2 := tc.pairing(framePSStart, tlvItem{tlvMethod, []byte{0}}, tlvItem{tlvState, []byte{1}})
	pin := <-h.pin
	sp, _ := srp.NewSRP("rfc5054.3072", sha512.New, kdfRFC2945([]byte("Pair-Setup")))
	cs := sp.NewClientSession([]byte("Pair-Setup"), []byte(pin))
	S, err := cs.ComputeKey(m2[tlvSalt], m2[tlvPublicKey])
	if err != nil {
		t.Fatal(err)
	}
	proof := cs.ComputeAuthenticator()
	m4 := tc.pairing(framePSNext, tlvItem{tlvState, []byte{3}}, tlvItem{tlvPublicKey, cs.GetA()}, tlvItem{tlvProof, proof})
	if tlvByte(m4, tlvError) >= 0 || !cs.VerifyServerAuthenticator(m4[tlvProof]) {
		t.Fatalf("M4 failed: %v", m4)
	}
	key := hkdfSHA512(S, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info")
	signIn := append(hkdfSHA512(S, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info"), ctrlID...)
	signIn = append(signIn, ctrlPub...)
	inner := tlvEncode(tlvItem{tlvIdentifier, ctrlID}, tlvItem{tlvPublicKey, ctrlPub},
		tlvItem{tlvSignature, ed25519.Sign(ctrlPriv, signIn)}, tlvItem{tlvInfo, opackEncode(map[string]any{"name": "iPhone"})})
	aead, _ := chacha20poly1305.New(key)
	m6 := tc.pairing(framePSNext, tlvItem{tlvState, []byte{5}}, tlvItem{tlvEncrypted, aead.Seal(nil, hapNonce("PS-Msg05"), inner, nil)})
	pt, err := aead.Open(nil, hapNonce("PS-Msg06"), m6[tlvEncrypted], nil)
	if err != nil {
		t.Fatal("M6 decrypt:", err)
	}
	acc := tlvDecode(pt)
	accSign := append(hkdfSHA512(S, "Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info"), acc[tlvIdentifier]...)
	accSign = append(accSign, acc[tlvPublicKey]...)
	if !ed25519.Verify(acc[tlvPublicKey], accSign, acc[tlvSignature]) {
		t.Fatal("accessory signature invalid")
	}
	c1.Close()

	// --- pair-verify on a new connection ---
	c2, _ := net.Dial("tcp", ln.Addr().String())
	tc = &testClient{t: t, c: c2}
	priv := randBytes(32)
	pub, _ := curve25519.X25519(priv, curve25519.Basepoint)
	v2 := tc.pairing(framePVStart, tlvItem{tlvState, []byte{1}}, tlvItem{tlvPublicKey, pub})
	shared, _ := curve25519.X25519(priv, v2[tlvPublicKey])
	vkey := hkdfSHA512(shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info")
	va, _ := chacha20poly1305.New(vkey)
	if _, err := va.Open(nil, hapNonce("PV-Msg02"), v2[tlvEncrypted], nil); err != nil {
		t.Fatal("PV M2 decrypt:", err)
	}
	msg := append(append(append([]byte{}, pub...), ctrlID...), v2[tlvPublicKey]...)
	inner = tlvEncode(tlvItem{tlvIdentifier, ctrlID}, tlvItem{tlvSignature, ed25519.Sign(ctrlPriv, msg)})
	v4 := tc.pairing(framePVNext, tlvItem{tlvState, []byte{3}}, tlvItem{tlvEncrypted, va.Seal(nil, hapNonce("PV-Msg03"), inner, nil)})
	if tlvByte(v4, tlvError) >= 0 {
		t.Fatalf("verify rejected: %v", v4)
	}
	tc.out, _ = chacha20poly1305.New(hkdfSHA512(shared, "", "ClientEncrypt-main"))
	tc.in, _ = chacha20poly1305.New(hkdfSHA512(shared, "", "ServerEncrypt-main"))

	// --- encrypted requests ---
	tc.send(frameEOpack, opackEncode(map[string]any{"_i": "_sessionStart", "_t": int64(2), "_x": int64(7),
		"_c": map[string]any{"_srvT": "com.apple.tvremoteservices", "_sid": int64(99)}}))
	_, resp := tc.recv()
	if x, _ := asInt(resp["_x"]); x != 7 || asMap(resp["_c"])["_sid"] == nil {
		t.Fatalf("bad _sessionStart response %v", resp)
	}
	tc.send(frameEOpack, opackEncode(map[string]any{"_i": "_hidC", "_t": int64(2), "_x": int64(8),
		"_c": map[string]any{"_hBtS": int64(1), "_hidC": int64(6)}}))
	tc.recv()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.buttons) != 1 || h.buttons[0] != "6:true" {
		t.Fatalf("buttons = %v", h.buttons)
	}

	// A different, unpaired controller must be rejected.
	c3, _ := net.Dial("tcp", ln.Addr().String())
	tc = &testClient{t: t, c: c3}
	v2 = tc.pairing(framePVStart, tlvItem{tlvState, []byte{1}}, tlvItem{tlvPublicKey, pub})
	shared, _ = curve25519.X25519(priv, v2[tlvPublicKey])
	va, _ = chacha20poly1305.New(hkdfSHA512(shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info"))
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	inner = tlvEncode(tlvItem{tlvIdentifier, []byte("STRANGER")}, tlvItem{tlvSignature, ed25519.Sign(otherPriv, msg)})
	v4 = tc.pairing(framePVNext, tlvItem{tlvState, []byte{3}}, tlvItem{tlvEncrypted, va.Seal(nil, hapNonce("PV-Msg03"), inner, nil)})
	if tlvByte(v4, tlvError) != tlvErrAuthentication {
		t.Fatalf("stranger not rejected: %v", v4)
	}
}

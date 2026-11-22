package companion

import (
	"context"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/brutella/dnssd"
	"github.com/tadglines/go-pkgs/crypto/srp"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Frame types.
const (
	frameNoOp    = 0x01
	framePSStart = 0x03
	framePSNext  = 0x04
	framePVStart = 0x05
	framePVNext  = 0x06
	frameUOpack  = 0x07
	frameEOpack  = 0x08
	framePOpack  = 0x09
)

// Handler receives remote-control input.
type Handler interface {
	// Button is called for _hidC events. code uses the Companion numbering
	// (1 up, 2 down, 3 left, 4 right, 5 menu, 6 select, 7 home, 8/9 volume, ...).
	Button(code int, down bool)
	// Touch is called for touchpad events. phase: 1 press, 2/3 move, 4 release, 5 tap.
	// x and y are normalised to 0..1.
	Touch(phase int, x, y float64)
	// ShowPin shows (or with "" hides) the pairing PIN on the TV.
	ShowPin(pin string)
}

// Server advertises a Companion Link service and accepts remote sessions.
type Server struct {
	Name    string
	Model   string // advertised model, e.g. "AppleTV6,2"
	DataDir string
	Port    int
	Ifaces  []string
	Handler Handler
	Debug   bool

	mu    sync.Mutex
	state storeState
	pin   string
}

type storeState struct {
	ID            string            `json:"id"`
	Seed          []byte            `json:"seed"`
	BTAddr        string            `json:"btaddr"`
	RapportID     string            `json:"rapportId"`
	MediaRemoteID string            `json:"mediaRemoteId"`
	Pairings      map[string][]byte `json:"pairings"` // controller id -> Ed25519 public key
}

func (s *Server) storePath() string { return filepath.Join(s.DataDir, "companion.json") }

func (s *Server) load() error {
	if b, err := os.ReadFile(s.storePath()); err == nil {
		if json.Unmarshal(b, &s.state) == nil && len(s.state.Seed) == ed25519.SeedSize {
			if s.state.Pairings == nil {
				s.state.Pairings = map[string][]byte{}
			}
			if s.state.RapportID == "" { // added after the first release
				s.state.RapportID = randHex(6)
				s.state.MediaRemoteID = newUUID()
				return s.save()
			}
			return nil
		}
	}
	s.state = storeState{
		ID:            strings.ToUpper(randHex(4) + "-" + randHex(2) + "-" + randHex(2) + "-" + randHex(2) + "-" + randHex(6)),
		Seed:          randBytes(ed25519.SeedSize),
		BTAddr:        macFrom(randBytes(6)),
		RapportID:     randHex(6),
		MediaRemoteID: newUUID(),
		Pairings:      map[string][]byte{},
	}
	return s.save()
}

func (s *Server) save() error {
	b, _ := json.MarshalIndent(s.state, "", "  ")
	return os.WriteFile(s.storePath(), b, 0o600)
}

func (s *Server) key() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(s.state.Seed) }

// PendingPin returns the PIN currently being shown, if any.
func (s *Server) PendingPin() string { s.mu.Lock(); defer s.mu.Unlock(); return s.pin }

// Paired reports how many iOS devices are paired.
func (s *Server) Paired() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.state.Pairings) }

func (s *Server) setPin(p string) {
	s.mu.Lock()
	changed := s.pin != p
	s.pin = p
	s.mu.Unlock()
	if changed && s.Handler != nil {
		s.Handler.ShowPin(p)
	}
}

func (s *Server) debugf(format string, a ...any) {
	if s.Debug {
		log.Printf("companion: "+format, a...)
	}
}

// ListenAndServe runs until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.Model == "" {
		s.Model = "AppleTV6,2"
	}
	if err := os.MkdirAll(s.DataDir, 0o700); err != nil {
		return err
	}
	if err := s.load(); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.Port))
	if err != nil {
		return err
	}
	s.Port = ln.Addr().(*net.TCPAddr).Port
	go func() { <-ctx.Done(); ln.Close() }()

	rp, err := dnssd.NewResponder()
	if err != nil {
		return err
	}
	svc, err := dnssd.NewService(dnssd.Config{
		Name:   s.Name,
		Type:   "_companion-link._tcp",
		Domain: "local",
		Host:   "tvbridge-" + strings.ToLower(strings.ReplaceAll(s.state.ID[:8], "-", "")),
		Port:   s.Port,
		Ifaces: s.Ifaces,
		Text: map[string]string{
			// These values are known to make iOS 27 list the device in the remote.
			// (rpFl=0xB6782 + rpMac=2 + rpMd=AppleTV5,3 made it disappear.)
			"rpMd": s.Model,
			"rpFl": "0x36782",
			"rpVr": "195.2",
			"rpHA": randHex(6),
			"rpHN": randHex(6),
			"rpAD": randHex(6),
			"rpHI": randHex(6),
			"rpBA": s.state.BTAddr,
		},
	})
	if err != nil {
		return err
	}
	if _, err := rp.Add(svc); err != nil {
		return err
	}
	go rp.Respond(ctx)
	log.Printf("companion: advertising %q (%s) on port %d", s.Name, s.Model, s.Port)

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go (&conn{s: s, c: c}).serve()
	}
}

// ---- per-connection state -------------------------------------------------

type conn struct {
	s  *Server
	c  net.Conn
	wm sync.Mutex

	// pair-setup
	srp      *srp.ServerSession
	srpS     []byte
	setupKey []byte

	// pair-verify
	pvPriv, pvPub []byte
	pvPeer        []byte
	pvShared      []byte
	pvKey         []byte

	// encrypted session
	out, in        cipher.AEAD
	outN, inN      uint64
	sid            uint64
	touchW, touchH float64
	volume         float64 // last volume reported to iOS (0..1)
}

func (c *conn) serve() {
	defer c.c.Close()
	defer c.s.setPin("") // abandon any pairing in progress
	peer := c.c.RemoteAddr().String()
	c.s.debugf("connect %s", peer)
	c.touchW, c.touchH = 1000, 1000
	c.volume = 0.5
	hdr := make([]byte, 4)
	for {
		c.c.SetReadDeadline(time.Now().Add(10 * time.Minute))
		if _, err := io.ReadFull(c.c, hdr); err != nil {
			c.s.debugf("disconnect %s: %v", peer, err)
			return
		}
		n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
		if n > 1<<20 {
			return
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(c.c, payload); err != nil {
			return
		}
		if c.in != nil && n > 0 {
			nonce := make([]byte, 12)
			binary.LittleEndian.PutUint64(nonce, c.inN)
			c.inN++
			pt, err := c.in.Open(nil, nonce, payload, hdr)
			if err != nil {
				log.Printf("companion: decrypt failed from %s: %v", peer, err)
				return
			}
			payload = pt
		}
		if err := c.handle(hdr[0], payload); err != nil {
			log.Printf("companion: %s: %v", peer, err)
			return
		}
	}
}

func (c *conn) send(typ byte, payload []byte) error {
	c.wm.Lock()
	defer c.wm.Unlock()
	n := len(payload)
	if c.out != nil && n > 0 {
		n += c.out.Overhead()
	}
	hdr := []byte{typ, byte(n >> 16), byte(n >> 8), byte(n)}
	if c.out != nil && len(payload) > 0 {
		nonce := make([]byte, 12)
		binary.LittleEndian.PutUint64(nonce, c.outN)
		c.outN++
		payload = c.out.Seal(nil, nonce, payload, hdr)
	}
	c.c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := c.c.Write(append(hdr, payload...))
	return err
}

func (c *conn) sendPairing(typ byte, items ...tlvItem) error {
	return c.send(typ, opackEncode(map[string]any{"_pd": tlvEncode(items...)}))
}

func (c *conn) handle(typ byte, payload []byte) error {
	switch typ {
	case frameNoOp:
		return nil
	case framePSStart, framePSNext:
		m, err := c.pairingTLV(payload)
		if err != nil {
			return err
		}
		return c.pairSetup(m)
	case framePVStart, framePVNext:
		m, err := c.pairingTLV(payload)
		if err != nil {
			return err
		}
		return c.pairVerify(m)
	case frameEOpack, frameUOpack, framePOpack:
		v, err := opackDecode(payload)
		if err != nil {
			return err
		}
		return c.message(typ, asMap(v))
	default:
		c.s.debugf("ignoring frame type 0x%02x (%d bytes)", typ, len(payload))
		return nil
	}
}

func (c *conn) pairingTLV(payload []byte) (map[byte][]byte, error) {
	v, err := opackDecode(payload)
	if err != nil {
		return nil, err
	}
	pd, ok := asMap(v)["_pd"].([]byte)
	if !ok {
		return nil, errors.New("pairing frame without _pd")
	}
	return tlvDecode(pd), nil
}

// ---- pair-setup (HAP SRP-6a, PIN shown on the TV) -------------------------

func hkdfSHA512(secret []byte, salt, info string) []byte {
	out := make([]byte, 32)
	io.ReadFull(hkdf.New(sha512.New, secret, []byte(salt), []byte(info)), out)
	return out
}

func hapNonce(s string) []byte { return append([]byte{0, 0, 0, 0}, s...) }

func (c *conn) pairSetup(m map[byte][]byte) error {
	switch tlvByte(m, tlvState) {
	case 1:
		pin := fmt.Sprintf("%04d", randInt(10000))
		s, err := srp.NewSRP("rfc5054.3072", sha512.New, kdfRFC2945([]byte("Pair-Setup")))
		if err != nil {
			return err
		}
		s.SaltLength = 16
		salt, v, err := s.ComputeVerifier([]byte(pin))
		if err != nil {
			return err
		}
		c.srp = s.NewServerSession([]byte("Pair-Setup"), salt, v)
		c.s.setPin(pin)
		log.Printf("companion: pairing requested, PIN %s shown on TV", pin)
		return c.sendPairing(framePSNext,
			tlvItem{tlvState, []byte{2}}, tlvItem{tlvSalt, salt},
			tlvItem{tlvPublicKey, c.srp.GetB()}, tlvItem{tlvFlags, []byte{1}})
	case 3:
		if c.srp == nil {
			return c.sendPairing(framePSNext, tlvItem{tlvState, []byte{4}}, tlvItem{tlvError, []byte{tlvErrAuthentication}})
		}
		S, err := c.srp.ComputeKey(m[tlvPublicKey])
		if err != nil || !c.srp.VerifyClientAuthenticator(m[tlvProof]) {
			log.Printf("companion: wrong PIN entered")
			return c.sendPairing(framePSNext, tlvItem{tlvState, []byte{4}}, tlvItem{tlvError, []byte{tlvErrAuthentication}})
		}
		c.srpS = S
		c.setupKey = hkdfSHA512(S, "Pair-Setup-Encrypt-Salt", "Pair-Setup-Encrypt-Info")
		return c.sendPairing(framePSNext, tlvItem{tlvState, []byte{4}}, tlvItem{tlvProof, c.srp.ComputeAuthenticator(m[tlvProof])})
	case 5:
		if c.setupKey == nil {
			return errors.New("pair-setup M5 before M3")
		}
		aead, _ := chacha20poly1305.New(c.setupKey)
		pt, err := aead.Open(nil, hapNonce("PS-Msg05"), m[tlvEncrypted], nil)
		if err != nil {
			return c.sendPairing(framePSNext, tlvItem{tlvState, []byte{6}}, tlvItem{tlvError, []byte{tlvErrAuthentication}})
		}
		sub := tlvDecode(pt)
		id, ltpk, sig := sub[tlvIdentifier], sub[tlvPublicKey], sub[tlvSignature]
		info := append(hkdfSHA512(c.srpS, "Pair-Setup-Controller-Sign-Salt", "Pair-Setup-Controller-Sign-Info"), id...)
		info = append(info, ltpk...)
		if len(ltpk) != ed25519.PublicKeySize || !ed25519.Verify(ltpk, info, sig) {
			return c.sendPairing(framePSNext, tlvItem{tlvState, []byte{6}}, tlvItem{tlvError, []byte{tlvErrAuthentication}})
		}
		if devInfo, err := opackDecode(sub[tlvInfo]); err == nil {
			c.s.debugf("controller info: %v", devInfo)
		}

		key := c.s.key()
		ourID := []byte(c.s.state.ID)
		ourPub := key.Public().(ed25519.PublicKey)
		accInfo := append(hkdfSHA512(c.srpS, "Pair-Setup-Accessory-Sign-Salt", "Pair-Setup-Accessory-Sign-Info"), ourID...)
		accInfo = append(accInfo, ourPub...)
		devInfo := opackEncode(map[string]any{
			"name":    c.s.Name,
			"model":   c.s.Model,
			"altIRK":  randBytes(16),
			"btAddr":  c.s.state.BTAddr,
			"mac":     randBytes(6),
			"wifiMAC": randBytes(6),
		})
		inner := tlvEncode(tlvItem{tlvIdentifier, ourID}, tlvItem{tlvPublicKey, ourPub},
			tlvItem{tlvSignature, ed25519.Sign(key, accInfo)}, tlvItem{tlvInfo, devInfo})
		ct := aead.Seal(nil, hapNonce("PS-Msg06"), inner, nil)

		c.s.mu.Lock()
		c.s.state.Pairings[string(id)] = ltpk
		err = c.s.save()
		c.s.mu.Unlock()
		if err != nil {
			log.Printf("companion: saving pairing: %v", err)
		}
		log.Printf("companion: paired with %s", id)
		c.s.setPin("")
		return c.sendPairing(framePSNext, tlvItem{tlvState, []byte{6}}, tlvItem{tlvEncrypted, ct})
	}
	return fmt.Errorf("unexpected pair-setup state %d", tlvByte(m, tlvState))
}

func kdfRFC2945(id []byte) srp.KeyDerivationFunc {
	return func(salt, pin []byte) []byte {
		h := sha512.New()
		h.Write(id)
		h.Write([]byte(":"))
		h.Write(pin)
		inner := h.Sum(nil)
		h.Reset()
		h.Write(salt)
		h.Write(inner)
		return h.Sum(nil)
	}
}

// ---- pair-verify (X25519 + Ed25519) ----------------------------------------

func (c *conn) pairVerify(m map[byte][]byte) error {
	switch tlvByte(m, tlvState) {
	case 1:
		c.pvPeer = m[tlvPublicKey]
		c.pvPriv = randBytes(32)
		c.pvPub, _ = curve25519.X25519(c.pvPriv, curve25519.Basepoint)
		shared, err := curve25519.X25519(c.pvPriv, c.pvPeer)
		if err != nil {
			return err
		}
		c.pvShared = shared
		c.pvKey = hkdfSHA512(shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info")
		ourID := []byte(c.s.state.ID)
		msg := append(append(append([]byte{}, c.pvPub...), ourID...), c.pvPeer...)
		inner := tlvEncode(tlvItem{tlvIdentifier, ourID}, tlvItem{tlvSignature, ed25519.Sign(c.s.key(), msg)})
		aead, _ := chacha20poly1305.New(c.pvKey)
		ct := aead.Seal(nil, hapNonce("PV-Msg02"), inner, nil)
		return c.sendPairing(framePVNext, tlvItem{tlvState, []byte{2}}, tlvItem{tlvPublicKey, c.pvPub}, tlvItem{tlvEncrypted, ct})
	case 3:
		fail := func(why string) error {
			c.s.debugf("pair-verify rejected: %s", why)
			return c.sendPairing(framePVNext, tlvItem{tlvState, []byte{4}}, tlvItem{tlvError, []byte{tlvErrAuthentication}})
		}
		if c.pvKey == nil {
			return fail("M3 before M1")
		}
		aead, _ := chacha20poly1305.New(c.pvKey)
		pt, err := aead.Open(nil, hapNonce("PV-Msg03"), m[tlvEncrypted], nil)
		if err != nil {
			return fail("decrypt")
		}
		sub := tlvDecode(pt)
		id := string(sub[tlvIdentifier])
		c.s.mu.Lock()
		ltpk := c.s.state.Pairings[id]
		c.s.mu.Unlock()
		if ltpk == nil {
			return fail("unknown controller " + id)
		}
		msg := append(append(append([]byte{}, c.pvPeer...), sub[tlvIdentifier]...), c.pvPub...)
		if !ed25519.Verify(ltpk, msg, sub[tlvSignature]) {
			return fail("bad signature")
		}
		if err := c.sendPairing(framePVNext, tlvItem{tlvState, []byte{4}}); err != nil {
			return err
		}
		c.out, _ = chacha20poly1305.New(hkdfSHA512(c.pvShared, "", "ServerEncrypt-main"))
		c.in, _ = chacha20poly1305.New(hkdfSHA512(c.pvShared, "", "ClientEncrypt-main"))
		c.outN, c.inN = 0, 0
		log.Printf("companion: session established with %s", id)
		return nil
	}
	return fmt.Errorf("unexpected pair-verify state %d", tlvByte(m, tlvState))
}

// ---- encrypted session messages --------------------------------------------

func (c *conn) message(typ byte, m map[string]any) error {
	id, _ := m["_i"].(string)
	t, _ := asInt(m["_t"])
	content := asMap(m["_c"])
	switch id {
	case "_hidT": // too chatty to log
	case "_systemInfo", "PublishPresenceEvent": // contain Apple account identifiers; log keys only
		keys := make([]string, 0, len(content))
		for k := range content {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		c.s.debugf("<- %s t=%d keys=%v", id, t, keys)
	default:
		c.s.debugf("<- %s t=%d %v", id, t, content)
	}

	var reply map[string]any // nil = generic empty response
	switch id {
	case "_hidC":
		code, _ := asInt(content["_hidC"])
		state, _ := asInt(content["_hBtS"])
		if c.s.Handler != nil {
			c.s.Handler.Button(int(code), state == 1)
		}
	case "_hidT":
		phase, _ := asInt(content["_tPh"])
		x := asFloat(content["_cx"]) / c.touchW
		y := asFloat(content["_cy"]) / c.touchH
		if c.s.Handler != nil {
			c.s.Handler.Touch(int(phase), x, y)
		}
	case "_touchStart":
		if w := asFloat(content["_width"]); w > 0 {
			c.touchW = w
		}
		if h := asFloat(content["_height"]); h > 0 {
			c.touchH = h
		}
		reply = map[string]any{"_i": int64(1)}
	case "_sessionStart":
		c.sid = uint64(randInt(1 << 31))
		reply = map[string]any{"_sid": int64(c.sid)}
	case "_systemInfo":
		// The base set got iOS 27 through the full session start. Adding _i,
		// _mrID, _mRtID, _lP, _clFl or _sf made it stall right after this reply,
		// so those are deliberately left out.
		reply = map[string]any{
			"name":   c.s.Name,
			"model":  c.s.Model,
			"_idsID": c.s.state.ID,
			"_pubID": c.s.state.BTAddr,
			"_sv":    "195.2",
			"_bf":    int64(1920),
			"_cf":    int64(512),
			"_stA":   []any{"com.apple.tvremoteservices"},
			"_msSt":  int64(1),
			"_msRo":  int64(1),
			"_dCapF": int64(1),
			"_siriInfo": map[string]any{
				"peerData": map[string]any{"userInterfaceIdiom": "ZEUS"}, // Apple TV
			},
		}
	case "TVRCSessionStart":
		reply = content // a real Apple TV echoes {ProtocolVersionKey: ...}
	case "FetchAttentionState":
		reply = map[string]any{"state": int64(3)} // awake
	case "FetchMediaControlStatus":
		reply = map[string]any{"MediaControlFlags": int64(mcfPlay | mcfPause | mcfVolume)}
	case "_interest":
		for _, ev := range asSlice(content["_regEvents"]) {
			if ev == "_iMC" || ev == "MediaControlStatus" {
				c.event(fmt.Sprint(ev), map[string]any{"_mcF": int64(mcfPlay | mcfPause | mcfVolume)})
			}
		}
	case "MediaControlCommand", "_mcc":
		reply = c.mediaControl(content)
	}

	if t != 2 { // only requests get a response
		return nil
	}
	if reply == nil {
		reply = map[string]any{}
	}
	resp := map[string]any{"_c": reply, "_t": int64(3)} // iOS hangs up if "_i" is echoed
	if x, ok := m["_x"]; ok {
		resp["_x"] = x
	}
	return c.send(frameEOpack, opackEncode(resp))
}

// Media control flags (_mcF).
const (
	mcfPlay   = 0x1
	mcfPause  = 0x2
	mcfVolume = 0x100
)

// mediaControl handles MediaControlCommand requests (numbering from pyatv).
func (c *conn) mediaControl(content map[string]any) map[string]any {
	cmd, _ := asInt(content["MediaControlCommand"])
	if cmd == 0 {
		cmd, _ = asInt(content["_mcc"])
	}
	press := func(code int) {
		if c.s.Handler != nil {
			c.s.Handler.Button(code, true)
		}
	}
	switch cmd {
	case 1, 2: // Play, Pause
		press(14)
	case 3: // NextTrack
		press(hidNextTrack)
	case 4: // PreviousTrack
		press(hidPrevTrack)
	case 5: // GetVolume
		return map[string]any{"_vol": c.volume}
	case 6: // SetVolume: TV volume is relative, so step towards the request
		if v := asFloat(content["_vol"]); v > c.volume {
			press(8)
			c.volume = v
		} else if v < c.volume {
			press(9)
			c.volume = v
		}
	default:
		c.s.debugf("media control command %d ignored", cmd)
	}
	return map[string]any{}
}

// Pseudo HID codes (beyond Apple's range) for track skipping.
const (
	hidNextTrack = 100
	hidPrevTrack = 101
)

func (c *conn) event(id string, content map[string]any) {
	c.send(frameEOpack, opackEncode(map[string]any{"_i": id, "_t": int64(1), "_c": content, "_x": int64(randInt(1 << 30))}))
}

func asSlice(v any) []any { s, _ := v.([]any); return s }

// ---- small helpers ------------------------------------------------------------

func newUUID() string {
	return strings.ToUpper(randHex(4) + "-" + randHex(2) + "-" + randHex(2) + "-" + randHex(2) + "-" + randHex(6))
}

func randBytes(n int) []byte { b := make([]byte, n); rand.Read(b); return b }
func randHex(n int) string   { return hex.EncodeToString(randBytes(n)) }
func randInt(n int64) int64 {
	v, _ := rand.Int(rand.Reader, big.NewInt(n))
	return v.Int64()
}
func macFrom(b []byte) string {
	return strings.ToUpper(fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", (b[0]|0x02)&^0x01, b[1], b[2], b[3], b[4], b[5]))
}

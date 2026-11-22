// tvbridge exposes an Android/Google TV to HomeKit as a Television accessory so
// it can be driven from the iOS Control Center remote. Key presses are
// forwarded over the Android TV Remote Service v2 protocol.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/brutella/hap"
	"github.com/brutella/hap/accessory"
	"github.com/brutella/hap/characteristic"
	haplog "github.com/brutella/hap/log"
	"github.com/brutella/hap/service"

	"tvbridge/adb"
	"tvbridge/atv"
	"tvbridge/companion"
	"tvbridge/uinput"
)

// backend delivers Android keycodes to the TV.
type backend interface {
	Press(androidKey int) error
	IsOn() bool
	Connected() bool
}

type remoteBackend struct{ r *atv.Remote }

func (b remoteBackend) Press(k int) error { return b.r.SendKey(k) }
func (b remoteBackend) IsOn() bool        { return b.r.IsOn() }
func (b remoteBackend) Connected() bool   { return b.r.Connected() }

type uinputBackend struct {
	dev *uinput.Device
	on  atomic.Bool
}

func (b *uinputBackend) Press(k int) error { return b.dev.Press(k) }
func (b *uinputBackend) IsOn() bool        { return b.on.Load() }
func (b *uinputBackend) Connected() bool   { return true }

// pollPower tracks screen state with dumpsys (a native binary, cheap to run).
func (b *uinputBackend) pollPower(report func(bool)) {
	first := true
	for {
		out, err := exec.Command("/system/bin/dumpsys", "power").Output()
		if err == nil {
			on := bytes.Contains(out, []byte("mWakefulness=Awake"))
			if first || on != b.on.Load() {
				b.on.Store(on)
				report(on)
				first = false
			}
		}
		time.Sleep(10 * time.Second)
	}
}

// HomeKit RemoteKey -> Android keycode. The Control Center remote has no Home
// button for HomeKit TVs, so the (i) Info key is mapped to Home.
var keyMap = map[int]int{
	characteristic.RemoteKeyArrowUp:     atv.KeyDpadUp,
	characteristic.RemoteKeyArrowDown:   atv.KeyDpadDown,
	characteristic.RemoteKeyArrowLeft:   atv.KeyDpadLeft,
	characteristic.RemoteKeyArrowRight:  atv.KeyDpadRight,
	characteristic.RemoteKeySelect:      atv.KeyDpadCenter,
	characteristic.RemoteKeyBack:        atv.KeyBack,
	characteristic.RemoteKeyExit:        atv.KeyHome,
	characteristic.RemoteKeyPlayPause:   atv.KeyPlayPause,
	characteristic.RemoteKeyInfo:        atv.KeyHome,
	characteristic.RemoteKeyRewind:      atv.KeyRewind,
	characteristic.RemoteKeyFastForward: atv.KeyFastFwd,
	characteristic.RemoteKeyNextTrack:   atv.KeyNext,
	characteristic.RemoteKeyPrevTrack:   atv.KeyPrevious,
}

func main() {
	var (
		tvHost   = flag.String("tv", "127.0.0.1", "Android TV address (127.0.0.1 when running on the TV)")
		dataDir  = flag.String("data", "./data", "directory for keys and pairing state")
		name     = flag.String("name", "Google TV", "name shown in HomeKit")
		pin      = flag.String("pin", "", "8-digit HomeKit setup code (random and persisted if empty)")
		ifaces   = flag.String("iface", "", "comma-separated network interfaces to advertise on (default all)")
		httpAddr = flag.String("http", "127.0.0.1:8899", "control API address (pairing/status)")
		keyMapS  = flag.String("keymap", "", "override key mapping, e.g. 15=82,10=3 (HomeKit key=Android keycode)")
		launch   = flag.String("launch", "", "launcher mode: path of this binary inside the APK; starts the bridge as the shell user via the TV's own adbd")
		debugF   = flag.Bool("debug", false, "log HomeKit protocol traffic")
		hapPort  = flag.Int("port", 51827, "HomeKit TCP port (fixed so iOS's cached address stays valid)")
		compF    = flag.Bool("companion", true, "also appear as an Apple TV to the iOS Control Center remote")
		pinActF  = flag.String("pin-activity", "dev.couchtv.ontv/.AppleRemoteActivity", "activity that shows the iPhone pairing PIN on the TV (am start -n)")
		backendF = flag.String("backend", "auto", "auto | uinput (on the TV, run via adb shell) | remote (Remote Service v2 over the network)")
	)
	flag.Parse()
	pinActivity = *pinActF
	debug.SetGCPercent(50) // trade a little CPU for a smaller heap on low-RAM TVs
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatal(err)
	}
	if *launch != "" {
		os.Exit(runLauncher(*launch, *dataDir, *name))
	}
	for _, kv := range strings.Split(*keyMapS, ",") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			hk, e1 := strconv.Atoi(k)
			ak, e2 := strconv.Atoi(v)
			if e1 == nil && e2 == nil {
				keyMap[hk] = ak
			}
		}
	}

	cert, err := atv.LoadOrCreateCert(*dataDir)
	if err != nil {
		log.Fatalf("client cert: %v", err)
	}
	setupCode := loadPin(*dataDir, *pin)

	// ---- HomeKit accessory ----
	tv := accessory.NewTelevision(accessory.Info{
		Name:         *name,
		Manufacturer: "tvbridge",
		Model:        "Android TV Remote Bridge",
		SerialNumber: "TVB-1",
		Firmware:     "1.0.0",
	})
	// The Control Center remote only picks up TVs whose Television service is primary.
	tv.Television.Primary = true
	tv.Television.ConfiguredName.SetValue(*name)
	tv.Television.SleepDiscoveryMode.SetValue(characteristic.SleepDiscoveryModeAlwaysDiscoverable)
	tv.Television.ActiveIdentifier.SetValue(1)

	remoteKey := characteristic.NewRemoteKey()
	tv.Television.AddC(remoteKey.C)

	// Match what HAP-NodeJS/Homebridge TVs publish (those show up in the remote):
	// a Name on the TV service, Power Mode Selection, and Protocol Information.
	tvName := characteristic.NewName()
	tvName.SetValue(*name)
	tv.Television.AddC(tvName.C)
	powerMode := characteristic.NewPowerModeSelection()
	tv.Television.AddC(powerMode.C)
	proto := service.NewProtocolInformation()
	proto.Version.SetValue("1.1.0")
	tv.AddS(proto.S)
	spkName := characteristic.NewName()
	spkName.SetValue(*name + " Speaker")
	tv.Speaker.AddC(spkName.C)

	// Relative volume via the phone's hardware buttons.
	volCtl := characteristic.NewVolumeControlType()
	volCtl.SetValue(characteristic.VolumeControlTypeRelative)
	volSel := characteristic.NewVolumeSelector()
	spkActive := characteristic.NewActive()
	spkActive.SetValue(characteristic.ActiveActive)
	tv.Speaker.AddC(spkActive.C)
	tv.Speaker.AddC(volCtl.C)
	tv.Speaker.AddC(volSel.C)
	tv.Television.AddS(tv.Speaker.S)

	// A single input so the Home app renders the tile properly.
	in := service.NewInputSource()
	in.ConfiguredName.SetValue("Google TV")
	in.InputSourceType.SetValue(characteristic.InputSourceTypeOther)
	in.IsConfigured.SetValue(characteristic.IsConfiguredConfigured)
	in.CurrentVisibilityState.SetValue(characteristic.CurrentVisibilityStateShown)
	in.AddC(identifier(1))
	inName := characteristic.NewName()
	inName.SetValue("Google TV")
	in.AddC(inName.C)
	tv.AddS(in.S)
	tv.Television.AddS(in.S)

	// ---- Android TV remote ----
	remote := &atv.Remote{
		Host: *tvHost,
		Cert: cert,
		OnPower: func(on bool) {
			v := characteristic.ActiveInactive
			if on {
				v = characteristic.ActiveActive
			}
			tv.Television.Active.SetValue(v)
		},
		OnAuthFailed: func() {
			log.Printf("atv: TV rejected our certificate - pair via: curl -X POST http://%s/pair/start", *httpAddr)
		},
	}

	// Pick how key presses reach the TV.
	var be backend = remoteBackend{remote}
	useUinput := *backendF == "uinput"
	if *backendF == "auto" {
		_, err := os.Stat("/system/bin/app_process") // running on Android itself
		useUinput = err == nil
	}
	if useUinput {
		dev, err := uinput.Open("tvbridge remote")
		if err != nil {
			log.Fatalf("%v (the uinput backend must run as the adb shell user)", err)
		}
		defer dev.Close()
		ub := &uinputBackend{dev: dev}
		go ub.pollPower(func(on bool) { remote.OnPower(on) })
		be = ub
		log.Printf("backend: uinput virtual remote")
	} else {
		go remote.Run(nil)
		log.Printf("backend: Android TV Remote v2 at %s", *tvHost)
	}

	send := func(code int) {
		if err := be.Press(code); err != nil {
			log.Printf("key %d: %v", code, err)
		}
	}
	remoteKey.OnValueRemoteUpdate(func(v int) {
		if code, ok := keyMap[v]; ok {
			send(code)
		}
	})
	volSel.OnValueRemoteUpdate(func(v int) {
		if v == characteristic.VolumeSelectorIncrement {
			send(atv.KeyVolumeUp)
		} else {
			send(atv.KeyVolumeDown)
		}
	})
	tv.Speaker.Mute.OnValueRemoteUpdate(func(bool) { send(atv.KeyMute) })
	tv.Television.Active.OnValueRemoteUpdate(func(v int) {
		want := v == characteristic.ActiveActive
		if want != be.IsOn() {
			if _, ok := be.(*uinputBackend); ok {
				if want {
					send(224) // KEYCODE_WAKEUP
				} else {
					send(223) // KEYCODE_SLEEP
				}
			} else {
				send(atv.KeyPower)
			}
		}
	})
	tv.Television.ActiveIdentifier.OnValueRemoteUpdate(func(int) {})
	powerMode.OnValueRemoteUpdate(func(int) { send(atv.KeyMenu) }) // "View TV Settings"

	server, err := hap.NewServer(hap.NewFsStore(filepath.Join(*dataDir, "hap")), tv.A)
	if err != nil {
		log.Fatal(err)
	}
	server.Pin = setupCode
	server.Addr = fmt.Sprintf(":%d", *hapPort)
	if *debugF {
		haplog.Debug.Enable()
	}
	if *ifaces != "" {
		server.Ifaces = strings.Split(*ifaces, ",")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var comp *companion.Server
	if *compF {
		comp = &companion.Server{
			Name:    *name,
			DataDir: *dataDir,
			Ifaces:  server.Ifaces,
			Debug:   *debugF,
			Handler: &remoteInput{send: send},
		}
		go func() {
			if err := comp.ListenAndServe(ctx); err != nil {
				log.Printf("companion: %v", err)
			}
		}()
	}
	go serveControl(*httpAddr, *tvHost, cert, remote, be, server, comp, setupCode, send)

	log.Printf("HomeKit setup code: %s-%s-%s (Home app > Add Accessory > More options)",
		setupCode[:3], setupCode[3:5], setupCode[5:])
	if err := server.ListenAndServe(ctx); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}

func identifier(v int) *characteristic.C {
	c := characteristic.NewIdentifier()
	c.SetValue(v)
	return c.C
}

// loadPin returns the configured setup code, or a random one persisted in dir.
func loadPin(dir, flagPin string) string {
	if p := strings.ReplaceAll(flagPin, "-", ""); p != "" {
		return p
	}
	path := filepath.Join(dir, "setup-code")
	if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) == 8 {
		return strings.TrimSpace(string(b))
	}
	invalid := map[string]bool{"12345678": true, "87654321": true}
	for {
		n, _ := rand.Int(rand.Reader, big.NewInt(100000000))
		p := fmt.Sprintf("%08d", n.Int64())
		if invalid[p] || strings.Count(p, p[:1]) == 8 {
			continue
		}
		os.WriteFile(path, []byte(p+"\n"), 0o600)
		return p
	}
}

// serveControl exposes a tiny local HTTP API used for pairing and diagnostics.
func serveControl(addr, tvHost string, cert tls.Certificate, remote *atv.Remote, be backend, server *hap.Server, comp *companion.Server, code string, send func(int)) {
	var mu sync.Mutex
	var pairing *atv.Pairing
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		var compPin string
		compPaired := 0
		if comp != nil {
			compPin, compPaired = comp.PendingPin(), comp.Paired()
		}
		reply(w, 200, map[string]any{
			"companionPin":    compPin,
			"companionPaired": compPaired,
			"tvConnected":     be.Connected(),
			"tvOn":            be.IsOn(),
			"backend":         fmt.Sprintf("%T", be),
			"homekitPaired":   server.IsPaired(),
			"homekitCode":     code,
			"tvHost":          tvHost,
			"pairingPending":  pairing != nil,
		})
	})
	mux.HandleFunc("POST /pair/start", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if pairing != nil {
			pairing.Close()
		}
		p, err := atv.StartPairing(tvHost, cert, "tvbridge")
		if err != nil {
			reply(w, 502, map[string]string{"error": err.Error()})
			return
		}
		pairing = p
		reply(w, 200, map[string]string{"status": "enter the 6-character code shown on the TV via /pair/finish?code=XXXXXX"})
	})
	mux.HandleFunc("POST /pair/finish", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if pairing == nil {
			reply(w, 409, map[string]string{"error": "call /pair/start first"})
			return
		}
		err := pairing.Finish(r.URL.Query().Get("code"))
		pairing = nil
		if err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		remote.Kick()
		reply(w, 200, map[string]string{"status": "paired"})
	})
	mux.HandleFunc("POST /key", func(w http.ResponseWriter, r *http.Request) {
		c, err := strconv.Atoi(r.URL.Query().Get("code"))
		if err != nil {
			reply(w, 400, map[string]string{"error": "code must be an Android keycode"})
			return
		}
		send(c)
		reply(w, 200, map[string]string{"status": "sent"})
	})
	log.Printf("control API on http://%s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("control API: %v", err)
	}
}

// runLauncher runs inside the APK (app uid). It asks the TV's own adbd to start
// the bridge as the shell user, which is what allows /dev/uinput access.
func runLauncher(self, keyDir, name string) int {
	key, err := adb.LoadOrCreateKey(keyDir)
	if err != nil {
		log.Printf("launcher: %v", err)
		return 1
	}
	const bin, dir = "/data/local/tmp/tvbridge", "/data/local/tmp/tvb"
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	script := fmt.Sprintf(`mkdir -p %[2]s
if ! cmp -s %[3]s %[1]s; then kill $(pidof tvbridge) 2>/dev/null; sleep 1; cp %[3]s %[1]s && chmod 755 %[1]s; fi
if pidof tvbridge >/dev/null; then echo running; else
cd %[2]s && (setsid nohup %[1]s -data %[2]s -name %[4]s -http 127.0.0.1:8899 > %[2]s/log.txt 2>&1 < /dev/null &) ; sleep 1; pidof tvbridge >/dev/null && echo started || echo failed; fi`,
		bin, dir, q(self), q(name))
	deadline := time.Now().Add(10 * time.Minute) // adbd may come up late after boot
	for {
		out, err := adb.Shell("127.0.0.1:5555", key, script, 2*time.Minute)
		if err == nil {
			log.Printf("launcher: %s", strings.TrimSpace(out))
			if strings.Contains(out, "failed") {
				return 1
			}
			return 0
		}
		log.Printf("launcher: %v", err)
		if time.Now().After(deadline) {
			return 1
		}
		time.Sleep(10 * time.Second)
	}
}

// remoteInput turns iOS remote input (Companion HID events) into Android keys.
type remoteInput struct {
	send func(int)

	mu               sync.Mutex
	touching         bool
	anchorX, anchorY float64
}

// Companion _hidC button codes -> Android keycodes.
var hidButtons = map[int]int{
	1: atv.KeyDpadUp, 2: atv.KeyDpadDown, 3: atv.KeyDpadLeft, 4: atv.KeyDpadRight,
	5: atv.KeyBack, 6: atv.KeyDpadCenter, 7: atv.KeyHome,
	8: atv.KeyVolumeUp, 9: atv.KeyVolumeDown,
	12: 223 /* SLEEP */, 13: 224 /* WAKEUP */, 14: atv.KeyPlayPause,
	18:  atv.KeyMute,                       // iOS 27 remote's mute button (pyatv calls 18 "PageUp")
	100: atv.KeyNext, 101: atv.KeyPrevious, // companion.hidNextTrack / hidPrevTrack
}

func (r *remoteInput) Button(code int, down bool) {
	if !down {
		return
	}
	if k, ok := hidButtons[code]; ok {
		r.send(k)
	} else {
		log.Printf("companion: unmapped remote button %d", code)
	}
}

// swipeStep is how far (as a fraction of the touchpad) a finger must travel
// to produce one arrow press; long swipes produce several.
const swipeStep = 0.12

func (r *remoteInput) Touch(phase int, x, y float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch phase {
	case 1: // press
		r.touching, r.anchorX, r.anchorY = true, x, y
	case 2, 3: // move (iOS 27 sends 2; older iOS 3)
		if !r.touching {
			r.touching, r.anchorX, r.anchorY = true, x, y
			return
		}
		dx, dy := x-r.anchorX, y-r.anchorY
		ax, ay := dx, dy
		if ax < 0 {
			ax = -ax
		}
		if ay < 0 {
			ay = -ay
		}
		if ax < swipeStep && ay < swipeStep {
			return
		}
		switch {
		case ax >= ay && dx > 0:
			r.send(atv.KeyDpadRight)
		case ax >= ay:
			r.send(atv.KeyDpadLeft)
		case dy > 0:
			r.send(atv.KeyDpadDown)
		default:
			r.send(atv.KeyDpadUp)
		}
		r.anchorX, r.anchorY = x, y
	case 4: // release
		r.touching = false
	}
}

// pinActivity is the app screen that shows the pairing PIN (couch-tv's on-TV app by default).
var pinActivity = "dev.couchtv.ontv/.AppleRemoteActivity"

// ShowPin displays the pairing PIN through the on-TV app.
func (r *remoteInput) ShowPin(pin string) {
	if pin == "" {
		return // the app closes itself once pairing finishes (it polls /status)
	}
	log.Printf("companion: showing PIN %s on screen", pin)
	out, err := exec.Command("/system/bin/am", "start", "-n", pinActivity, "--es", "pin", pin).CombinedOutput()
	if err != nil {
		log.Printf("companion: could not show PIN on TV (%v): %s", err, out)
	}
}

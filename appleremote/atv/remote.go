package atv

import (
	"bufio"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

// Android KeyEvent codes used by the bridge.
const (
	KeyHome       = 3
	KeyBack       = 4
	KeyDpadUp     = 19
	KeyDpadDown   = 20
	KeyDpadLeft   = 21
	KeyDpadRight  = 22
	KeyDpadCenter = 23
	KeyVolumeUp   = 24
	KeyVolumeDown = 25
	KeyPower      = 26
	KeyMenu       = 82
	KeyPlayPause  = 85
	KeyNext       = 87
	KeyPrevious   = 88
	KeyRewind     = 89
	KeyFastFwd    = 90
	KeyMute       = 164
	KeyInfo       = 165
)

// RemoteMessage field numbers.
const (
	rConfigure     = 1
	rSetActive     = 2
	rError         = 3
	rPingRequest   = 8
	rPingResponse  = 9
	rKeyInject     = 10
	rStart         = 40
	rSetVolume     = 50
	directionShort = 3
	featureCode    = 622 // feature bitmask the official app advertises
)

var ErrNotConnected = errors.New("atv: not connected to TV")

// Remote keeps a persistent connection to the TV's remote service and
// reconnects automatically.
type Remote struct {
	Host string
	Cert tls.Certificate
	// OnPower is called when the TV reports its screen on/off state.
	OnPower func(on bool)
	// OnAuthFailed is called when the TV refuses the client cert (needs pairing).
	OnAuthFailed func()

	mu        sync.Mutex
	conn      *tls.Conn
	ready     bool
	on        bool
	authFails int
	kick      chan struct{}
}

func (r *Remote) kickCh() chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.kick == nil {
		r.kick = make(chan struct{}, 1)
	}
	return r.kick
}

func (r *Remote) Connected() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.ready }
func (r *Remote) IsOn() bool      { r.mu.Lock(); defer r.mu.Unlock(); return r.on }

// Run maintains the connection until stop is closed.
func (r *Remote) Run(stop <-chan struct{}) {
	backoff := time.Second
	for {
		start := time.Now()
		err := r.session(stop)
		select {
		case <-stop:
			return
		default:
		}
		if time.Since(start) > 30*time.Second {
			backoff = time.Second
		}
		log.Printf("atv: remote session ended: %v (retry in %s)", err, backoff)
		select {
		case <-stop:
			return
		case <-time.After(backoff):
		case <-r.kickCh():
			backoff = time.Second
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// Kick drops the current connection so Run reconnects immediately (e.g. after pairing).
func (r *Remote) Kick() {
	r.mu.Lock()
	if r.conn != nil {
		r.conn.Close()
	}
	r.mu.Unlock()
	select {
	case r.kickCh() <- struct{}{}:
	default:
	}
}

func (r *Remote) session(stop <-chan struct{}) error {
	d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 15 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(r.Host, "6466"), tlsConfig(r.Cert))
	if err != nil {
		var opErr *net.OpError
		if !errors.As(err, &opErr) || opErr.Op != "dial" {
			r.authFailed() // handshake rejected => cert not paired
		}
		return err
	}
	r.mu.Lock()
	r.conn = conn
	r.mu.Unlock()
	defer func() {
		conn.Close()
		r.mu.Lock()
		r.conn, r.ready = nil, false
		r.mu.Unlock()
	}()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-stop:
			conn.Close()
		case <-done:
		}
	}()

	br := bufio.NewReader(conn)
	gotAny := false
	for {
		// TV pings every ~5s; a long silence means the link is dead.
		conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		b, err := readFrame(br)
		if err != nil {
			if !gotAny {
				r.authFailed() // TV closes immediately when the cert is unknown
			}
			return err
		}
		gotAny = true
		f, err := parse(b)
		if err != nil {
			return err
		}
		switch {
		case f.has(rConfigure):
			info := msg{}.str(1, "tvbridge").str(2, "tvbridge").varint(3, 1).str(4, "1").
				str(5, "tvbridge").str(6, "1.0.0")
			r.write(msg{}.bytes(rConfigure, msg{}.varint(1, featureCode).bytes(2, info)))
		case f.has(rSetActive):
			r.write(msg{}.bytes(rSetActive, msg{}.varint(1, featureCode)))
			r.mu.Lock()
			if !r.ready {
				log.Printf("atv: connected to %s", r.Host)
			}
			r.ready, r.authFails = true, 0
			r.mu.Unlock()
		case f.has(rPingRequest):
			p, _ := parse(f.b[rPingRequest])
			r.write(msg{}.bytes(rPingResponse, msg{}.varint(1, p.v[1])))
		case f.has(rStart):
			s, _ := parse(f.b[rStart])
			on := s.v[1] != 0
			r.mu.Lock()
			r.on = on
			cb := r.OnPower
			r.mu.Unlock()
			if cb != nil {
				cb(on)
			}
		case f.has(rError):
			log.Printf("atv: TV reported an error message")
		}
	}
}

func (r *Remote) authFailed() {
	r.mu.Lock()
	r.authFails++
	n, cb := r.authFails, r.OnAuthFailed
	r.mu.Unlock()
	if n == 2 && cb != nil {
		cb()
	}
}

func (r *Remote) write(m msg) error {
	r.mu.Lock()
	c := r.conn
	r.mu.Unlock()
	if c == nil {
		return ErrNotConnected
	}
	c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return writeFrame(c, m)
}

// SendKey sends a short press of an Android keycode.
func (r *Remote) SendKey(code int) error {
	if !r.Connected() {
		return ErrNotConnected
	}
	return r.write(msg{}.bytes(rKeyInject, msg{}.varint(1, uint64(code)).varint(2, directionShort)))
}

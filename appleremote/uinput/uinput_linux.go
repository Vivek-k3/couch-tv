// Package uinput creates a virtual remote-control input device via /dev/uinput.
// On Android the shell user (adb) can open /dev/uinput, so a bridge running on
// the TV itself can inject key presses that look like a hardware remote.
package uinput

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	evSyn = 0x00
	evKey = 0x01

	uiSetEvBit   = 0x40045564 // _IOW('U', 100, int)
	uiSetKeyBit  = 0x40045565 // _IOW('U', 101, int)
	uiDevCreate  = 0x5501     // _IO('U', 1)
	uiDevDestroy = 0x5502     // _IO('U', 2)
)

// Android keycode -> Linux input key code, resolved through Android's Generic.kl.
var androidToLinux = map[int]uint16{
	3:   172, // HOME      <- KEY_HOMEPAGE
	4:   158, // BACK      <- KEY_BACK
	19:  103, // DPAD_UP   <- KEY_UP
	20:  108, // DPAD_DOWN <- KEY_DOWN
	21:  105, // DPAD_LEFT <- KEY_LEFT
	22:  106, // DPAD_RIGHT<- KEY_RIGHT
	23:  353, // DPAD_CENTER <- KEY_SELECT
	24:  115, // VOLUME_UP
	25:  114, // VOLUME_DOWN
	26:  116, // POWER
	82:  139, // MENU
	85:  164, // MEDIA_PLAY_PAUSE <- KEY_PLAYPAUSE
	87:  163, // MEDIA_NEXT <- KEY_NEXTSONG
	88:  165, // MEDIA_PREVIOUS <- KEY_PREVIOUSSONG
	89:  168, // MEDIA_REWIND
	90:  208, // MEDIA_FAST_FORWARD
	164: 113, // VOLUME_MUTE <- KEY_MUTE
	165: 358, // INFO
	223: 142, // SLEEP
	224: 143, // WAKEUP
}

// inputEvent matches struct input_event (timeval uses native long size).
type inputEvent struct {
	Sec, Usec uintptr
	Type      uint16
	Code      uint16
	Value     int32
}

// Device is a virtual remote.
type Device struct {
	mu sync.Mutex
	f  *os.File
}

func ioctl(fd uintptr, req, arg uintptr) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, arg); e != 0 {
		return e
	}
	return nil
}

// Open creates the virtual device. It needs write access to /dev/uinput.
func Open(name string) (*Device, error) {
	f, err := os.OpenFile("/dev/uinput", os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("uinput: %w", err)
	}
	fd := f.Fd()
	if err := ioctl(fd, uiSetEvBit, evKey); err != nil {
		f.Close()
		return nil, fmt.Errorf("uinput: set EV_KEY: %w", err)
	}
	for _, k := range androidToLinux {
		if err := ioctl(fd, uiSetKeyBit, uintptr(k)); err != nil {
			f.Close()
			return nil, fmt.Errorf("uinput: set key %d: %w", k, err)
		}
	}
	// Legacy struct uinput_user_dev: name[80], input_id{bustype,vendor,product,version u16},
	// ff_effects_max u32, absmax/absmin/absfuzz/absflat [64]s32.
	var dev bytes.Buffer
	nb := make([]byte, 80)
	copy(nb, name)
	dev.Write(nb)
	binary.Write(&dev, binary.LittleEndian, [4]uint16{0x06 /*BUS_VIRTUAL*/, 0x1209, 0x7476, 1})
	dev.Write(make([]byte, 4+4*64*4))
	if _, err := f.Write(dev.Bytes()); err != nil {
		f.Close()
		return nil, fmt.Errorf("uinput: write device: %w", err)
	}
	if err := ioctl(fd, uiDevCreate, 0); err != nil {
		f.Close()
		return nil, fmt.Errorf("uinput: create: %w", err)
	}
	time.Sleep(300 * time.Millisecond) // let InputReader pick the device up
	return &Device{f: f}, nil
}

func (d *Device) emit(typ, code uint16, val int32) error {
	ev := inputEvent{Type: typ, Code: code, Value: val}
	b := (*[unsafe.Sizeof(ev)]byte)(unsafe.Pointer(&ev))[:]
	_, err := d.f.Write(b)
	return err
}

// Supported reports whether an Android keycode can be injected.
func Supported(androidKey int) bool { _, ok := androidToLinux[androidKey]; return ok }

// Press sends a short press of an Android keycode.
func (d *Device) Press(androidKey int) error {
	k, ok := androidToLinux[androidKey]
	if !ok {
		return fmt.Errorf("uinput: unsupported keycode %d", androidKey)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, v := range []int32{1, 0} {
		if err := d.emit(evKey, k, v); err != nil {
			return err
		}
		if err := d.emit(evSyn, 0, 0); err != nil {
			return err
		}
		if v == 1 {
			time.Sleep(30 * time.Millisecond)
		}
	}
	return nil
}

// Close destroys the device.
func (d *Device) Close() error {
	ioctl(d.f.Fd(), uiDevDestroy, 0)
	return d.f.Close()
}

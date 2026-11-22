// Package companion implements enough of Apple's Companion Link protocol (the
// one iOS's Control Center remote uses to talk to an Apple TV) to receive
// remote-control input: discovery, HAP-style pairing, the encrypted session and
// HID button/touch events.
package companion

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
)

// OPACK is Apple's private binary serialization (CoreUtils). Values decode to:
// bool, nil, int64, float64, string, []byte, []any, map[string]any.

func opackEncode(v any) []byte { return appendOpack(nil, v) }

func appendOpack(b []byte, v any) []byte {
	switch x := v.(type) {
	case nil:
		return append(b, 0x04)
	case bool:
		if x {
			return append(b, 0x01)
		}
		return append(b, 0x02)
	case int:
		return appendInt(b, int64(x))
	case int64:
		return appendInt(b, x)
	case uint64:
		return appendInt(b, int64(x))
	case float64:
		b = append(b, 0x36)
		return binary.LittleEndian.AppendUint64(b, math.Float64bits(x))
	case string:
		n := len(x)
		switch {
		case n <= 0x20:
			b = append(b, byte(0x40+n))
		case n <= 0xff:
			b = append(b, 0x61, byte(n))
		case n <= 0xffff:
			b = binary.LittleEndian.AppendUint16(append(b, 0x62), uint16(n))
		default:
			b = binary.LittleEndian.AppendUint32(append(b, 0x64), uint32(n))
		}
		return append(b, x...)
	case []byte:
		n := len(x)
		switch {
		case n <= 0x20:
			b = append(b, byte(0x70+n))
		case n <= 0xff:
			b = append(b, 0x91, byte(n))
		case n <= 0xffff:
			b = binary.LittleEndian.AppendUint16(append(b, 0x92), uint16(n))
		default:
			b = binary.LittleEndian.AppendUint32(append(b, 0x94), uint32(n))
		}
		return append(b, x...)
	case []any:
		if len(x) < 15 {
			b = append(b, byte(0xd0+len(x)))
			for _, e := range x {
				b = appendOpack(b, e)
			}
			return b
		}
		b = append(b, 0xdf)
		for _, e := range x {
			b = appendOpack(b, e)
		}
		return append(b, 0x03)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys) // deterministic output
		if len(x) < 15 {
			b = append(b, byte(0xe0+len(x)))
		} else {
			b = append(b, 0xef)
		}
		for _, k := range keys {
			b = appendOpack(b, k)
			b = appendOpack(b, x[k])
		}
		if len(x) >= 15 {
			b = append(b, 0x03)
		}
		return b
	default:
		panic(fmt.Sprintf("opack: unsupported type %T", v))
	}
}

func appendInt(b []byte, v int64) []byte {
	switch {
	case v == -1:
		return append(b, 0x07)
	case v >= 0 && v <= 0x27:
		return append(b, byte(0x08+v))
	case v >= 0 && v <= 0xff:
		return append(b, 0x30, byte(v))
	case v >= 0 && v <= 0xffff:
		return binary.LittleEndian.AppendUint16(append(b, 0x31), uint16(v))
	case v >= 0 && v <= 0xffffffff:
		return binary.LittleEndian.AppendUint32(append(b, 0x32), uint32(v))
	default:
		return binary.LittleEndian.AppendUint64(append(b, 0x33), uint64(v))
	}
}

var errShort = errors.New("opack: truncated data")

type opackDecoder struct {
	b    []byte
	objs []any // back-reference table for pointer tags
}

func opackDecode(b []byte) (any, error) {
	d := &opackDecoder{b: b}
	v, err := d.value()
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (d *opackDecoder) take(n int) ([]byte, error) {
	if n < 0 || len(d.b) < n {
		return nil, errShort
	}
	out := d.b[:n]
	d.b = d.b[n:]
	return out, nil
}

func (d *opackDecoder) uintN(n int) (uint64, error) {
	raw, err := d.take(n)
	if err != nil {
		return 0, err
	}
	var v uint64
	for i := n - 1; i >= 0; i-- {
		v = v<<8 | uint64(raw[i])
	}
	return v, nil
}

var lenBytes = [4]int{1, 2, 3, 4}

func (d *opackDecoder) value() (any, error) {
	if len(d.b) == 0 {
		return nil, errShort
	}
	start := len(d.b)
	t := d.b[0]
	d.b = d.b[1:]
	var v any
	var err error
	container := false
	switch {
	case t == 0x01:
		v = true
	case t == 0x02:
		v = false
	case t == 0x04:
		v = nil
	case t == 0x05: // UUID
		v, err = d.take(16)
	case t == 0x06: // absolute time, 8 bytes
		var u uint64
		u, err = d.uintN(8)
		v = int64(u)
	case t == 0x07:
		v = int64(-1)
	case t >= 0x08 && t <= 0x2f:
		v = int64(t - 0x08)
	case t >= 0x30 && t <= 0x33:
		var u uint64
		u, err = d.uintN(1 << (t - 0x30))
		v = int64(u)
	case t == 0x35:
		var u uint64
		u, err = d.uintN(4)
		v = float64(math.Float32frombits(uint32(u)))
	case t == 0x36:
		var u uint64
		u, err = d.uintN(8)
		v = math.Float64frombits(u)
	case t >= 0x40 && t <= 0x60:
		var raw []byte
		raw, err = d.take(int(t - 0x40))
		v = string(raw)
	case t >= 0x61 && t <= 0x64:
		var n uint64
		if n, err = d.uintN(lenBytes[t-0x61]); err == nil {
			var raw []byte
			raw, err = d.take(int(n))
			v = string(raw)
		}
	case t == 0x6f: // NUL-terminated string
		i := 0
		for i < len(d.b) && d.b[i] != 0 {
			i++
		}
		if i == len(d.b) {
			return nil, errShort
		}
		v = string(d.b[:i])
		d.b = d.b[i+1:]
	case t >= 0x70 && t <= 0x90:
		var raw []byte
		raw, err = d.take(int(t - 0x70))
		v = append([]byte(nil), raw...)
	case t >= 0x91 && t <= 0x94:
		var n uint64
		if n, err = d.uintN(lenBytes[t-0x91]); err == nil {
			var raw []byte
			raw, err = d.take(int(n))
			v = append([]byte(nil), raw...)
		}
	case t >= 0xa0 && t <= 0xc0:
		return d.pointer(int(t - 0xa0))
	case t >= 0xc1 && t <= 0xc4:
		var idx uint64
		if idx, err = d.uintN(lenBytes[t-0xc1]); err != nil {
			return nil, err
		}
		return d.pointer(int(idx))
	case t >= 0xd0 && t <= 0xdf:
		container = true
		arr := []any{}
		count, endless := int(t&0x0f), t == 0xdf
		for i := 0; endless || i < count; i++ {
			if endless && len(d.b) > 0 && d.b[0] == 0x03 {
				d.b = d.b[1:]
				break
			}
			var e any
			if e, err = d.value(); err != nil {
				return nil, err
			}
			arr = append(arr, e)
		}
		v = arr
	case t >= 0xe0 && t <= 0xef:
		container = true
		m := map[string]any{}
		count, endless := int(t&0x0f), t == 0xef
		for i := 0; endless || i < count; i++ {
			if endless && len(d.b) > 0 && d.b[0] == 0x03 {
				d.b = d.b[1:]
				break
			}
			var k, e any
			if k, err = d.value(); err != nil {
				return nil, err
			}
			if e, err = d.value(); err != nil {
				return nil, err
			}
			m[fmt.Sprint(k)] = e
		}
		v = m
	default:
		return nil, fmt.Errorf("opack: unknown tag 0x%02x", t)
	}
	if err != nil {
		return nil, err
	}
	// Multi-byte scalars become pointer targets; containers and 1-byte values do not.
	if !container && start-len(d.b) > 1 {
		d.objs = append(d.objs, v)
	}
	return v, nil
}

func (d *opackDecoder) pointer(i int) (any, error) {
	if i >= len(d.objs) {
		return nil, fmt.Errorf("opack: bad pointer %d", i)
	}
	return d.objs[i], nil
}

// helpers for reading decoded maps

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

func asInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case float64:
		return int64(x), true
	case string: // "_t" is sometimes sent as a string
		var n int64
		_, err := fmt.Sscan(x, &n)
		return n, err == nil
	}
	return 0, false
}

func asFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int64:
		return float64(x)
	}
	return 0
}

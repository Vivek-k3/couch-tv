package atv

import (
	"bufio"
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	big := bytes.Repeat([]byte{7}, 300) // forces a 2-byte varint length
	for _, payload := range [][]byte{{}, {1, 2, 3}, big} {
		var buf bytes.Buffer
		if err := writeFrame(&buf, payload); err != nil {
			t.Fatal(err)
		}
		got, err := readFrame(bufio.NewReader(&buf))
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("round trip %d bytes: got %d, err %v", len(payload), len(got), err)
		}
	}
}

func TestKeyInjectEncoding(t *testing.T) {
	// RemoteMessage{remote_key_inject{key_code: 19, direction: SHORT}}
	m := msg{}.bytes(rKeyInject, msg{}.varint(1, KeyDpadUp).varint(2, directionShort))
	want := []byte{0x52, 0x04, 0x08, 0x13, 0x10, 0x03}
	if !bytes.Equal(m, want) {
		t.Fatalf("got % x want % x", []byte(m), want)
	}
	f, err := parse(m)
	if err != nil || !f.has(rKeyInject) {
		t.Fatal("parse failed")
	}
	inner, _ := parse(f.b[rKeyInject])
	if inner.v[1] != KeyDpadUp || inner.v[2] != directionShort {
		t.Fatalf("bad inner %v", inner.v)
	}
}

func TestPairingRequestEncoding(t *testing.T) {
	m := outer(fPairingRequest, msg{}.str(1, "atvremote").str(2, "x"))
	f, err := parse(m)
	if err != nil || f.v[1] != 2 || f.v[2] != statusOK || !f.has(fPairingRequest) {
		t.Fatalf("bad outer message: %v %v", f.v, err)
	}
}

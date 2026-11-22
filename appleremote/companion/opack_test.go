package companion

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Examples from pyatv's protocol documentation.
func TestOpackDocExamples(t *testing.T) {
	cases := []struct {
		hex  string
		want any
	}{
		{"17", int64(15)},
		{"3020", int64(32)},
		{"43666f6f", "foo"},
		{"72aabb", []byte{0xaa, 0xbb}},
		{"df416103", []any{"a"}},
		{"e3416102416244746573744163a2", map[string]any{"a": false, "b": "test", "c": "test"}},
	}
	for _, c := range cases {
		got, err := opackDecode(mustHex(c.hex))
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %#v err %v want %#v", c.hex, got, err, c.want)
		}
	}
}

// The first frame the iPhone sent to the probe (PV_Start).
func TestDecodeRealPairVerifyStart(t *testing.T) {
	raw := mustHex("e2455f617554790c435f7064912506010103207255b88e0ab62340acf4f0eda36717c9d0e42dd3126c1cb519043e6cd734f61e")
	v, err := opackDecode(raw)
	if err != nil {
		t.Fatal(err)
	}
	m := asMap(v)
	if n, _ := asInt(m["_auTy"]); n != 4 {
		t.Fatalf("_auTy = %v", m["_auTy"])
	}
	tlv := tlvDecode(m["_pd"].([]byte))
	if tlvByte(tlv, tlvState) != 1 || len(tlv[tlvPublicKey]) != 32 {
		t.Fatalf("bad pd: %v", tlv)
	}
}

func TestOpackRoundTrip(t *testing.T) {
	long := bytes.Repeat([]byte("x"), 300)
	in := map[string]any{
		"_i": "_hidC", "_t": int64(2), "_x": int64(123456),
		"_c":   map[string]any{"_hBtS": int64(1), "_hidC": int64(6)},
		"f":    1.5,
		"neg":  int64(-1),
		"long": string(long),
		"blob": long,
		"list": []any{true, false, nil, "a"},
	}
	out, err := opackDecode(opackEncode(in))
	if err != nil || !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip mismatch: %v\n%#v", err, out)
	}
}

func TestTLVFragmentation(t *testing.T) {
	big := bytes.Repeat([]byte{9}, 600)
	m := tlvDecode(tlvEncode(tlvItem{tlvState, []byte{2}}, tlvItem{tlvPublicKey, big}, tlvItem{tlvSalt, []byte{1, 2}}))
	if tlvByte(m, tlvState) != 2 || !bytes.Equal(m[tlvPublicKey], big) || len(m[tlvSalt]) != 2 {
		t.Fatal("tlv fragmentation round trip failed")
	}
}

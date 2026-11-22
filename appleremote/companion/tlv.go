package companion

// TLV8 as used by HAP pairing: values over 255 bytes are split into
// consecutive items with the same tag.

const (
	tlvMethod     = 0x00
	tlvIdentifier = 0x01
	tlvSalt       = 0x02
	tlvPublicKey  = 0x03
	tlvProof      = 0x04
	tlvEncrypted  = 0x05
	tlvState      = 0x06
	tlvError      = 0x07
	tlvSignature  = 0x0a
	tlvInfo       = 0x11 // OPACK device info dictionary (Companion extension)
	tlvFlags      = 0x1b

	tlvErrAuthentication = 0x02
	tlvErrUnavailable    = 0x06
	tlvErrBusy           = 0x07
)

type tlvItem struct {
	tag byte
	val []byte
}

func tlvEncode(items ...tlvItem) []byte {
	var b []byte
	for _, it := range items {
		v := it.val
		if len(v) == 0 {
			b = append(b, it.tag, 0)
			continue
		}
		for len(v) > 0 {
			n := min(len(v), 255)
			b = append(b, it.tag, byte(n))
			b = append(b, v[:n]...)
			v = v[n:]
		}
	}
	return b
}

func tlvDecode(b []byte) map[byte][]byte {
	m := map[byte][]byte{}
	last := -1
	for len(b) >= 2 {
		tag, n := b[0], int(b[1])
		if len(b) < 2+n {
			break
		}
		val := b[2 : 2+n]
		if int(tag) == last { // continuation of a fragmented value
			m[tag] = append(m[tag], val...)
		} else {
			m[tag] = append([]byte(nil), val...)
		}
		last = int(tag)
		b = b[2+n:]
	}
	return m
}

func tlvByte(m map[byte][]byte, tag byte) int {
	if v, ok := m[tag]; ok && len(v) == 1 {
		return int(v[0])
	}
	return -1
}

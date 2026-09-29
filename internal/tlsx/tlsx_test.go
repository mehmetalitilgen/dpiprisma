package tlsx

import (
	"bytes"
	"testing"
)

func TestNewX25519KeyLength(t *testing.T) {
	key, err := NewX25519Key()
	if err != nil {
		t.Fatalf("NewX25519Key: %v", err)
	}

	pub := key.PublicKey().Bytes()
	if len(pub) != 32 {
		t.Fatalf("public key length = %d, want 32", len(pub))
	}
}

func TestNewX25519KeyUnique(t *testing.T) {
	k1, err := NewX25519Key()
	if err != nil {
		t.Fatalf("NewX25519Key #1: %v", err)
	}
	k2, err := NewX25519Key()
	if err != nil {
		t.Fatalf("NewX25519Key #2: %v", err)
	}

	if bytes.Equal(k1.PublicKey().Bytes(), k2.PublicKey().Bytes()) {
		t.Fatal("two calls produced the same public key")
	}
}

func TestReaderU8(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    uint8
		wantOK  bool
		wantPos int
	}{
		{"empty", nil, 0, false, 0}, // for u8, "one byte short" is the empty input
		{"exact", []byte{0xAB}, 0xAB, true, 1},
		{"extra", []byte{0xAB, 0xCD}, 0xAB, true, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &reader{buf: tt.in}
			got, ok := r.u8()
			if got != tt.want || ok != tt.wantOK || r.pos != tt.wantPos {
				t.Errorf("u8() = (%#x, %v), pos %d; want (%#x, %v), pos %d",
					got, ok, r.pos, tt.want, tt.wantOK, tt.wantPos)
			}
		})
	}
}

func TestReaderU16(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    uint16
		wantOK  bool
		wantPos int
	}{
		{"empty", nil, 0, false, 0},
		{"one byte short", []byte{0x12}, 0, false, 0},
		{"exact", []byte{0x12, 0x34}, 0x1234, true, 2},
		{"extra", []byte{0x12, 0x34, 0x56}, 0x1234, true, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &reader{buf: tt.in}
			got, ok := r.u16()
			if got != tt.want || ok != tt.wantOK || r.pos != tt.wantPos {
				t.Errorf("u16() = (%#x, %v), pos %d; want (%#x, %v), pos %d",
					got, ok, r.pos, tt.want, tt.wantOK, tt.wantPos)
			}
		})
	}
}

func TestReaderU24(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    uint32
		wantOK  bool
		wantPos int
	}{
		{"empty", nil, 0, false, 0},
		{"one byte short", []byte{0x12, 0x34}, 0, false, 0},
		{"exact", []byte{0x12, 0x34, 0x56}, 0x123456, true, 3},
		{"extra", []byte{0x12, 0x34, 0x56, 0x78}, 0x123456, true, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &reader{buf: tt.in}
			got, ok := r.u24()
			if got != tt.want || ok != tt.wantOK || r.pos != tt.wantPos {
				t.Errorf("u24() = (%#x, %v), pos %d; want (%#x, %v), pos %d",
					got, ok, r.pos, tt.want, tt.wantOK, tt.wantPos)
			}
		})
	}
}

func TestReaderBytes(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		n       int
		want    []byte
		wantOK  bool
		wantPos int
	}{
		{"empty", nil, 3, nil, false, 0},
		{"empty zero length", nil, 0, nil, true, 0},
		{"one byte short", []byte{1, 2}, 3, nil, false, 0},
		{"exact", []byte{1, 2, 3}, 3, []byte{1, 2, 3}, true, 3},
		{"extra", []byte{1, 2, 3, 4}, 3, []byte{1, 2, 3}, true, 3},
		{"negative n", []byte{1, 2, 3}, -1, nil, false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &reader{buf: tt.in}
			got, ok := r.bytes(tt.n)
			if !bytes.Equal(got, tt.want) || ok != tt.wantOK || r.pos != tt.wantPos {
				t.Errorf("bytes(%d) = (%x, %v), pos %d; want (%x, %v), pos %d",
					tt.n, got, ok, r.pos, tt.want, tt.wantOK, tt.wantPos)
			}
		})
	}
}

func TestReaderVec8(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    []byte
		wantOK  bool
		wantPos int
	}{
		{"empty", nil, nil, false, 0},
		{"zero length", []byte{0x00}, nil, true, 1},
		{"one byte short", []byte{0x03, 'a', 'b'}, nil, false, 0}, // position must be restored
		{"exact", []byte{0x03, 'a', 'b', 'c'}, []byte("abc"), true, 4},
		{"extra", []byte{0x03, 'a', 'b', 'c', 'd'}, []byte("abc"), true, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &reader{buf: tt.in}
			got, ok := r.vec8()
			if !bytes.Equal(got, tt.want) || ok != tt.wantOK || r.pos != tt.wantPos {
				t.Errorf("vec8() = (%x, %v), pos %d; want (%x, %v), pos %d",
					got, ok, r.pos, tt.want, tt.wantOK, tt.wantPos)
			}
		})
	}
}

func TestReaderVec16(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		want    []byte
		wantOK  bool
		wantPos int
	}{
		{"empty", nil, nil, false, 0},
		{"short length prefix", []byte{0x00}, nil, false, 0},
		{"zero length", []byte{0x00, 0x00}, nil, true, 2},
		{"one byte short", []byte{0x00, 0x03, 'a', 'b'}, nil, false, 0}, // position must be restored
		{"exact", []byte{0x00, 0x03, 'a', 'b', 'c'}, []byte("abc"), true, 5},
		{"extra", []byte{0x00, 0x03, 'a', 'b', 'c', 'd'}, []byte("abc"), true, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &reader{buf: tt.in}
			got, ok := r.vec16()
			if !bytes.Equal(got, tt.want) || ok != tt.wantOK || r.pos != tt.wantPos {
				t.Errorf("vec16() = (%x, %v), pos %d; want (%x, %v), pos %d",
					got, ok, r.pos, tt.want, tt.wantOK, tt.wantPos)
			}
		})
	}
}

func TestAppendU8RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		v    uint8
		wire []byte
	}{
		{"zero", 0x00, []byte{0x00}},
		{"mid", 0x7F, []byte{0x7F}},
		{"max", 0xFF, []byte{0xFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := appendU8(nil, tt.v)
			if !bytes.Equal(b, tt.wire) {
				t.Fatalf("appendU8(nil, %#x) = %x; want %x", tt.v, b, tt.wire)
			}

			r := &reader{buf: b}
			got, ok := r.u8()
			if !ok || got != tt.v || r.pos != len(b) {
				t.Errorf("u8() = (%#x, %v), pos %d; want (%#x, true), pos %d",
					got, ok, r.pos, tt.v, len(b))
			}
		})
	}
}

func TestAppendU16RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		v    uint16
		wire []byte
	}{
		{"zero", 0x0000, []byte{0x00, 0x00}},
		{"big endian", 0x0102, []byte{0x01, 0x02}},
		{"max", 0xFFFF, []byte{0xFF, 0xFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := appendU16(nil, tt.v)
			if !bytes.Equal(b, tt.wire) {
				t.Fatalf("appendU16(nil, %#x) = %x; want %x", tt.v, b, tt.wire)
			}

			r := &reader{buf: b}
			got, ok := r.u16()
			if !ok || got != tt.v || r.pos != len(b) {
				t.Errorf("u16() = (%#x, %v), pos %d; want (%#x, true), pos %d",
					got, ok, r.pos, tt.v, len(b))
			}
		})
	}
}

func TestAppendU24RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		v    uint32
		wire []byte
	}{
		{"zero", 0x000000, []byte{0x00, 0x00, 0x00}},
		{"big endian", 0x010203, []byte{0x01, 0x02, 0x03}},
		{"max", 0xFFFFFF, []byte{0xFF, 0xFF, 0xFF}}, // largest value that fits: must be accepted
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, ok := appendU24(nil, tt.v)
			if !ok || !bytes.Equal(b, tt.wire) {
				t.Fatalf("appendU24(nil, %#x) = (%x, %v); want (%x, true)", tt.v, b, ok, tt.wire)
			}

			r := &reader{buf: b}
			got, ok := r.u24()
			if !ok || got != tt.v || r.pos != len(b) {
				t.Errorf("u24() = (%#x, %v), pos %d; want (%#x, true), pos %d",
					got, ok, r.pos, tt.v, len(b))
			}
		})
	}
}

func TestAppendVec8RoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		v      []byte
		header []byte
	}{
		{"empty", []byte{}, []byte{0x00}},
		{"short", []byte("abc"), []byte{0x03}},
		{"max", bytes.Repeat([]byte{'x'}, 0xFF), []byte{0xFF}}, // largest length that fits
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, ok := appendVec8(nil, tt.v)
			wire := append(append([]byte(nil), tt.header...), tt.v...)
			if !ok || !bytes.Equal(b, wire) {
				t.Fatalf("appendVec8(nil, %d bytes) = (%x, %v); want (%x, true)", len(tt.v), b, ok, wire)
			}

			r := &reader{buf: b}
			got, ok := r.vec8()
			if !ok || !bytes.Equal(got, tt.v) || r.pos != len(b) {
				t.Errorf("vec8() = (%x, %v), pos %d; want (%x, true), pos %d",
					got, ok, r.pos, tt.v, len(b))
			}
		})
	}
}

func TestAppendVec16RoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		v      []byte
		header []byte
	}{
		{"empty", []byte{}, []byte{0x00, 0x00}},
		{"short", []byte("abc"), []byte{0x00, 0x03}},
		{"over u8", bytes.Repeat([]byte{'x'}, 0x100), []byte{0x01, 0x00}},
		{"max", bytes.Repeat([]byte{'x'}, 0xFFFF), []byte{0xFF, 0xFF}}, // largest length that fits
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, ok := appendVec16(nil, tt.v)
			wire := append(append([]byte(nil), tt.header...), tt.v...)
			if !ok || !bytes.Equal(b, wire) {
				t.Fatalf("appendVec16(nil, %d bytes) = (%d bytes, %v); want (%d bytes, true)",
					len(tt.v), len(b), ok, len(wire))
			}

			r := &reader{buf: b}
			got, ok := r.vec16()
			if !ok || !bytes.Equal(got, tt.v) || r.pos != len(b) {
				t.Errorf("vec16() = (%d bytes, %v), pos %d; want (%d bytes, true), pos %d",
					len(got), ok, r.pos, len(tt.v), len(b))
			}
		})
	}
}

func TestAppendRejectsOverflow(t *testing.T) {
	tests := []struct {
		name string
		call func(b []byte) ([]byte, bool)
	}{
		{"u24 0x1000000", func(b []byte) ([]byte, bool) { return appendU24(b, 0x1000000) }},
		{"u24 max uint32", func(b []byte) ([]byte, bool) { return appendU24(b, 0xFFFFFFFF) }},
		{"vec8 256 bytes", func(b []byte) ([]byte, bool) { return appendVec8(b, make([]byte, 0x100)) }},
		{"vec16 65536 bytes", func(b []byte) ([]byte, bool) { return appendVec16(b, make([]byte, 0x10000)) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// len 2, cap 8: writing into the spare capacity would clobber the 0xEE sentinels.
			backing := []byte{0xAA, 0xBB, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE}
			in := backing[:2]
			want := append([]byte(nil), backing...)

			got, ok := tt.call(in)
			if ok {
				t.Fatal("ok = true; want false")
			}
			if len(got) != len(in) || cap(got) != cap(in) || &got[0] != &in[0] {
				t.Errorf("returned slice len %d cap %d; want the input slice (len %d cap %d)",
					len(got), cap(got), len(in), cap(in))
			}
			if !bytes.Equal(backing, want) {
				t.Errorf("backing array = %x; want %x (unchanged)", backing, want)
			}
		})
	}
}

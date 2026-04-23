package keywrap

import (
	"bytes"
	"errors"
	"testing"
)

// RFC 3394 §4.6 test vector: wrap 256 bits of key data with a
// 256-bit KEK.
func TestRFC3394Vector(t *testing.T) {
	kek := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
	}
	plaintext := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	}
	want := []byte{
		0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4,
		0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87, 0xF8, 0x26,
		0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26,
		0xCB, 0xC7, 0xF0, 0xE7, 0x1A, 0x99, 0xF4, 0x3B,
		0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21,
	}
	w, err := New(kek)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := w.Wrap(plaintext)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("wrapped mismatch\n got: % x\nwant: % x", got, want)
	}

	back, err := w.Unwrap(got)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(back, plaintext) {
		t.Fatalf("unwrap mismatch: got % x, want % x", back, plaintext)
	}
}

func TestRejectsBadInputs(t *testing.T) {
	if _, err := New(make([]byte, 16)); !errors.Is(err, ErrKEKLength) {
		t.Fatalf("short KEK: got %v, want ErrKEKLength", err)
	}

	w, err := New(make([]byte, KEKLen))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := w.Wrap(nil); !errors.Is(err, ErrPlaintextLength) {
		t.Fatalf("empty plaintext: got %v, want ErrPlaintextLength", err)
	}
	if _, err := w.Wrap(make([]byte, 7)); !errors.Is(err, ErrPlaintextLength) {
		t.Fatalf("non-8-multiple plaintext: got %v, want ErrPlaintextLength", err)
	}
	if _, err := w.Unwrap(make([]byte, 7)); !errors.Is(err, ErrWrappedLength) {
		t.Fatalf("short wrapped: got %v, want ErrWrappedLength", err)
	}
	// Correct length but invalid integrity.
	if _, err := w.Unwrap(make([]byte, 24)); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("zeroed wrapped: got %v, want ErrIntegrity", err)
	}
}

// TestAmortisation verifies that a single Wrapper instance can be
// reused across many operations (amortised key schedule).
func TestAmortisation(t *testing.T) {
	kek := make([]byte, KEKLen)
	for i := range kek {
		kek[i] = byte(i)
	}
	w, err := New(kek)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := range 16 {
		pt := bytes.Repeat([]byte{byte(i)}, 32)
		wrapped, err := w.Wrap(pt)
		if err != nil {
			t.Fatalf("Wrap #%d: %v", i, err)
		}
		back, err := w.Unwrap(wrapped)
		if err != nil {
			t.Fatalf("Unwrap #%d: %v", i, err)
		}
		if !bytes.Equal(back, pt) {
			t.Fatalf("round-trip #%d mismatch", i)
		}
	}
}

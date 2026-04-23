// Package keywrap implements RFC 3394 AES Key Wrap (AES-KW).
//
// The Key Server uses A256KW; a 256-bit KEK wraps content encryption
// keys with a length in bytes which is a positive multiple of 8. This
// package uses the default IV 0xA6A6A6A6A6A6A6A6 and the index-based
// formulation given in RFC 3394 s. 2.2.1.
//
// The Wrapper type can be used to amortise the per-KEK AES key schedule
// calculation across multiple Wrap/Unwrap calls; construct once with New,
// then reuse for every operation under that KEK. The Wrapper type is safe
// for concurrent use; the underlying cipher.Block is read-only after
// construction.
package keywrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	blockSize = 8
	ivHi      = 0xA6A6A6A6
	ivLo      = 0xA6A6A6A6

	// KEKLen is the required KEK length in bytes (A256KW).
	KEKLen = 32
)

var (
	// ErrKEKLength reports that a KEK is not exactly KEKLen bytes.
	ErrKEKLength = errors.New("keywrap: KEK must be 32 bytes (A256KW)")
	// ErrPlaintextLength reports that a plaintext is zero-length or not a
	// multiple of 8 bytes.
	ErrPlaintextLength = errors.New("keywrap: plaintext must be a positive multiple of 8 bytes")
	// ErrWrappedLength reports that a wrapped value has an invalid
	// length (less than 16 bytes or not a multiple of 8).
	ErrWrappedLength = errors.New("keywrap: wrapped value has invalid length")
	// ErrIntegrity reports that the integrity check over a wrapped
	// value failed (recovered IV did not match the default IV).
	ErrIntegrity = errors.New("keywrap: wrapped value failed integrity check")
)

// Wrapper performs AES-KW operations under a fixed 256-bit KEK. The
// AES key schedule is computed once at construction time and reused
// across all subsequent Wrap and Unwrap calls. Wrapper is safe for
// concurrent use.
type Wrapper struct {
	block cipher.Block
}

// New returns a Wrapper keyed by kek. kek must be exactly KEKLen
// (32) bytes.
func New(kek []byte) (*Wrapper, error) {
	if len(kek) != KEKLen {
		return nil, ErrKEKLength
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("keywrap: AES KEK: %w", err)
	}
	return &Wrapper{block: block}, nil
}

// Wrap returns the AES-KW wrapping of plaintext under w's KEK.
// plaintext must be a positive multiple of 8 bytes. The returned
// slice is newly allocated and has length len(plaintext)+8.
func (w *Wrapper) Wrap(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext)%blockSize != 0 {
		return nil, ErrPlaintextLength
	}

	n := len(plaintext) / blockSize
	out := make([]byte, (n+1)*blockSize)
	binary.BigEndian.PutUint32(out[0:4], ivHi)
	binary.BigEndian.PutUint32(out[4:8], ivLo)
	copy(out[blockSize:], plaintext)

	var buf [16]byte
	for j := range 6 {
		for i := 1; i <= n; i++ {
			copy(buf[:8], out[0:8])
			copy(buf[8:], out[i*blockSize:(i+1)*blockSize])
			w.block.Encrypt(buf[:], buf[:])
			t := uint64(n)*uint64(j) + uint64(i)
			hi := binary.BigEndian.Uint64(buf[0:8])
			hi ^= t
			binary.BigEndian.PutUint64(out[0:8], hi)
			copy(out[i*blockSize:(i+1)*blockSize], buf[8:])
		}
	}
	return out, nil
}

// Unwrap is the inverse of Wrap. It returns the recovered plaintext
// on success, or ErrIntegrity if the recovered IV does not match the
// default IV. The returned slice is newly allocated and has length
// len(wrapped)-8.
func (w *Wrapper) Unwrap(wrapped []byte) ([]byte, error) {
	if len(wrapped) < 2*blockSize || len(wrapped)%blockSize != 0 {
		return nil, ErrWrappedLength
	}

	n := len(wrapped)/blockSize - 1
	work := make([]byte, len(wrapped))
	copy(work, wrapped)

	var buf [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n)*uint64(j) + uint64(i)
			hi := binary.BigEndian.Uint64(work[0:8])
			hi ^= t
			binary.BigEndian.PutUint64(buf[0:8], hi)
			copy(buf[8:], work[i*blockSize:(i+1)*blockSize])
			w.block.Decrypt(buf[:], buf[:])
			copy(work[0:8], buf[:8])
			copy(work[i*blockSize:(i+1)*blockSize], buf[8:])
		}
	}

	var iv [8]byte
	binary.BigEndian.PutUint32(iv[0:4], ivHi)
	binary.BigEndian.PutUint32(iv[4:8], ivLo)
	if subtle.ConstantTimeCompare(work[0:8], iv[:]) != 1 {
		return nil, ErrIntegrity
	}
	out := make([]byte, n*blockSize)
	copy(out, work[blockSize:])
	return out, nil
}

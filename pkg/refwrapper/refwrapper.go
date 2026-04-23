// Package refwrapper frames CKAP opaque references (LeaseRefs and
// LKATs) using a byte string authentication primitive (pkg/wrapper).
//
// # Encoding domain
//
// Opaque references in the current version of CKAP take one of three forms:
//
//   - Lease References (non-captive keys);
//
//   - Lease References (captive keys);
//
//   - LKATs (used with captive keys).
//
// khaled uses a unified encoding for all of these and distinguishes them
// using the first byte of the authenticated plaintext:
//
//	LeaseRef (v=0 for non-captive; v=1 for captive)
//	  Wrap((v, leaseTimeMicroseconds, rootKeySeqNo, subepochIdx),
//	       AAD=attrSet)
//	LKAT (v=2)
//	  Wrap((v, leaseTimeMicroseconds, rootKeySeqNo, subepochIdx, attrSet),
//	       AAD=nil)
//
// Integers are encoded as 64-bit big-endian values.
package refwrapper

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/khaled/pkg/keyschedule"
	"github.com/messier-42/khaled/pkg/wrapper"
)

// ErrInvalidRef is returned when an opaque token cannot be
// authenticated or does not have the version byte the caller expected.
// Specific causes are not distinguished.
var ErrInvalidRef = errors.New("refwrapper: invalid lease ref or LKAT")

// Ref version bytes partition the three flavours of authenticated
// token this package produces.
const (
	versionLeaseRefNonCaptive byte = iota
	versionLeaseRefCaptive
	versionLKAT
)

// prefixLen is the length of the prefix common to all variants:
//
//	version || lease_time_micros(i64BE) || root_seqno(u64BE) || subepoch(u64BE).
const prefixLen = 1 + 8 + 8 + 8

// Codec wraps and unwraps LeaseRefs and LKATs using an underlying
// [wrapper.Wrapper]. It is stateless apart from the wrapper
// reference and safe for concurrent use.
type Codec struct {
	w wrapper.Wrapper
}

// New returns a Codec that frames refs using w.
func New(w wrapper.Wrapper) (*Codec, error) {
	if w == nil {
		return nil, errors.New("refwrapper: wrapper is required")
	}

	return &Codec{w: w}, nil
}

// WrapLeaseRef constructs an authenticated Lease Reference. captive determines
// whether the Lease Reference represents a Lease with a captive key. The
// canonically encoded Attribute Set is passed to the underlying wrapper as AAD, but
// is not included in the wrapped output.
func (c *Codec) WrapLeaseRef(ctx context.Context, info keyschedule.LeaseRefInfo, repr attrset.Repr, captive bool) ([]byte, error) {
	v := versionLeaseRefNonCaptive
	if captive {
		v = versionLeaseRefCaptive
	}
	plaintext := encodePrefix(v, info)
	return c.w.Wrap(ctx, plaintext, []byte(repr))
}

// UnwrapLeaseRef verifies an incoming Lease Reference and validates that it matches
// the caller's expectations. It returns the recovered LeaseRefInfo and
// captive/non-captive bit. Unexpected inputs (e.g. LKATs) are rejected with
// [ErrInvalidRef].
func (c *Codec) UnwrapLeaseRef(ctx context.Context, ref []byte, repr attrset.Repr) (keyschedule.LeaseRefInfo, bool, error) {
	plaintext, err := c.w.Unwrap(ctx, ref, []byte(repr))
	if err != nil {
		return keyschedule.LeaseRefInfo{}, false, ErrInvalidRef
	}
	if len(plaintext) != prefixLen {
		return keyschedule.LeaseRefInfo{}, false, ErrInvalidRef
	}

	v := plaintext[0]
	switch v {
	case versionLeaseRefNonCaptive, versionLeaseRefCaptive:
	default:
		return keyschedule.LeaseRefInfo{}, false, ErrInvalidRef
	}

	info := decodePrefix(plaintext)
	return info, v == versionLeaseRefCaptive, nil
}

// WrapLKAT constructs an authenticated LKAT with an embedded
// serialized Attribute Set.
func (c *Codec) WrapLKAT(ctx context.Context, info keyschedule.LeaseRefInfo, repr attrset.Repr) ([]byte, error) {
	plaintext := encodePrefix(versionLKAT, info)
	plaintext = append(plaintext, repr...)
	return c.w.Wrap(ctx, plaintext, nil)
}

// UnwrapLKAT verifies an incoming LKAT and returns the recovered
// LeaseRefInfo and Attribute Set. Unexpected inputs, such as Lease References,
// are rejected with [ErrInvalidRef].
func (c *Codec) UnwrapLKAT(ctx context.Context, lkat []byte) (keyschedule.LeaseRefInfo, attrset.Repr, error) {
	plaintext, err := c.w.Unwrap(ctx, lkat, nil)
	if err != nil {
		return keyschedule.LeaseRefInfo{}, "", ErrInvalidRef
	}
	if len(plaintext) < prefixLen {
		return keyschedule.LeaseRefInfo{}, "", ErrInvalidRef
	}
	if plaintext[0] != versionLKAT {
		return keyschedule.LeaseRefInfo{}, "", ErrInvalidRef
	}

	// Parse the common data.
	info := decodePrefix(plaintext)

	// Parse and validate the embedded attribute set.
	tail := plaintext[prefixLen:]
	if len(tail) == 0 {
		return keyschedule.LeaseRefInfo{}, "", ErrInvalidRef
	}

	attrSet, err := attrset.ReprFromBytes(tail)
	if err != nil {
		return keyschedule.LeaseRefInfo{}, "", ErrInvalidRef
	}

	return info, attrSet, nil
}

// encodePrefix encodes the fixed prefix shared by all three
// ref flavours.
func encodePrefix(version byte, info keyschedule.LeaseRefInfo) []byte {
	out := make([]byte, prefixLen)
	out[0] = version
	binary.BigEndian.PutUint64(out[1:9], uint64(info.Time.UnixMicro()))
	binary.BigEndian.PutUint64(out[9:17], info.RootSeqNum)
	binary.BigEndian.PutUint64(out[17:25], info.SubEpoch)
	return out
}

// decodePrefix parses the fixed prefix. It assumed the caller has already
// validated the length and version byte.
func decodePrefix(b []byte) keyschedule.LeaseRefInfo {
	return keyschedule.LeaseRefInfo{
		Time:       time.UnixMicro(int64(binary.BigEndian.Uint64(b[1:9]))).UTC(),
		RootSeqNum: binary.BigEndian.Uint64(b[9:17]),
		SubEpoch:   binary.BigEndian.Uint64(b[17:25]),
	}
}

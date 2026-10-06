package keyserver

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"

	"github.com/ldclabs/cose/iana"

	"github.com/messier-42/cabe-go/ckapraw"
)

// CKAP CBOR wire types live in [ckapraw]; this file only carries the
// khaled-specific COSE_Key construction for Lease Keys, which is
// Key Server behaviour rather than wire schema.

// gcmIVLen is the preferred AES-GCM IV length.
const gcmIVLen = 12

// newCOSESymmetricKey builds a COSE_Key for a Lease Key.
func newCOSESymmetricKey(keyBytes []byte) (ckapraw.COSEKey, error) {
	var alg int
	switch len(keyBytes) {
	case 16:
		alg = iana.AlgorithmA128GCM
	case 24:
		alg = iana.AlgorithmA192GCM
	case 32:
		alg = iana.AlgorithmA256GCM
	default:
		return ckapraw.COSEKey{}, fmt.Errorf("unexpected key size %d", len(keyBytes))
	}

	baseIV, err := hkdf.Key(sha256.New, keyBytes, nil, "khaled/cose-base-iv", gcmIVLen)
	if err != nil {
		return ckapraw.COSEKey{}, fmt.Errorf("IV derivation error: %w", err)
	}

	return ckapraw.COSEKey{
		iana.KeyParameterKty:        iana.KeyTypeSymmetric,
		iana.KeyParameterAlg:        alg,
		iana.KeyParameterBaseIV:     baseIV,
		iana.SymmetricKeyParameterK: keyBytes,
	}, nil
}

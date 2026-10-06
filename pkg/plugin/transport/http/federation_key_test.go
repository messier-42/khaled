package http

import (
	"bytes"
	"testing"

	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/ckapraw"
	"github.com/messier-42/khaled/pkg/keyserver"
)

func TestEncodeFullForeignLeaseKey(t *testing.T) {
	original := ckapraw.COSEKey{1: 4, 3: 2, 5: []byte("foreign-base"), -1: []byte("012345678901234567890123"), "extension": []byte("preserve")}
	in := keyserver.LKAI{NonCaptive: &keyserver.LKAINonCaptive{LeaseKey: original}}
	out, err := encodeLKAI(in)
	if err != nil {
		t.Fatal(err)
	}
	a, err := key.MarshalCBOR(original)
	if err != nil {
		t.Fatal(err)
	}
	b, err := key.MarshalCBOR(out.NonCaptive.LeaseKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("complete COSE key changed")
	}
	zeroLKAICleanup(in)()
	if !allZero(original[-1].([]byte)) {
		t.Fatal("secret not cleared")
	}
}

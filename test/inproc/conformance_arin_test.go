//go:build integration

package inproc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckap"

	"github.com/messier-42/khaled/test/ktutil"
)

// TestGetARINToken_ReturnsUnsupported pins khaled's documented stance
// that ARIN is not implemented in v1: GetARINToken must return a
// CKAP Error with CodeUnsupported. Test exists so that any future
// change which silently wires ARIN up (or, worse, returns CodeInternal
// from a half-implemented path) trips the suite.
func TestGetARINToken_ReturnsUnsupported(t *testing.T) {
	t.Parallel()

	srv := khaledtest.Start(t)
	client := srv.Client(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetARINToken(ctx, ckap.GetARINTokenRequest{})
	if err == nil {
		t.Fatalf("GetARINToken: want error, got resp=%+v", resp)
	}
	var cerr *ckap.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("GetARINToken: want *ckap.Error, got %T: %v", err, err)
	}
	if cerr.Code != cabe.CodeUnsupported {
		t.Errorf("GetARINToken: code = %d, want CodeUnsupported (%d) — %s",
			cerr.Code, cabe.CodeUnsupported, describeError(err))
	}
}

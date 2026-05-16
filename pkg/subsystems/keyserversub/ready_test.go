package keyserversub

import "testing"

func TestStackHealthyNil(t *testing.T) {
	var s *Stack
	if s.Healthy() {
		t.Errorf("nil Stack should not be healthy")
	}
}

func TestStackHealthyIncomplete(t *testing.T) {
	// A Stack missing any layer is not healthy. The store and
	// schedule fields are interface/pointer types, so a zero Stack
	// has them nil.
	if (&Stack{}).Healthy() {
		t.Errorf("Stack with no layers should not be healthy")
	}
}

package disk

import "testing"

func TestCurrentPanicsWhenInvariantIsBroken(t *testing.T) {
	source := &Source{}

	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatalf("expected Current to panic when neither current nor loadErr is set")
		}
	}()

	_, _ = source.Current()
}

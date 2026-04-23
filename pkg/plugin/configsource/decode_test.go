package configsource_test

import (
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/messier-42/khaled/pkg/plugin/configsource"
)

func TestDecodeCBOR_RejectsExcessiveNesting(t *testing.T) {
	// Build a nested structure beyond the 32-level limit: 40 nested
	// 1-item maps.
	var inner any = 42
	for range 40 {
		inner = map[any]any{"k": inner}
	}
	data, err := cbor.Marshal(inner)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := configsource.DecodeCBOR(data); err == nil {
		t.Fatalf("expected DecodeCBOR to reject deeply-nested input")
	}
}

func TestDecodeCBOR_RejectsDuplicateMapKeys(t *testing.T) {
	// Hand-assemble a CBOR map with duplicate keys. fxamacker's
	// encoder won't produce one, so craft the bytes directly:
	//   0xa2 (map, 2 pairs)
	//     0x61 0x61 (key "a") 0x01 (value 1)
	//     0x61 0x61 (key "a") 0x02 (value 2)
	data := []byte{0xa2, 0x61, 'a', 0x01, 0x61, 'a', 0x02}
	if _, err := configsource.DecodeCBOR(data); err == nil {
		t.Fatalf("expected DecodeCBOR to reject duplicate map keys")
	}
}

func TestDecodeCBOR_RejectsTrailingBytes(t *testing.T) {
	data, err := cbor.Marshal(map[string]any{"k": "v"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Append an extra byte past the first item.
	data = append(data, 0x00)
	if _, err := configsource.DecodeCBOR(data); err == nil {
		t.Fatalf("expected DecodeCBOR to reject trailing bytes")
	}
}

func TestDecodeCBOR_AcceptsRealisticConfig(t *testing.T) {
	data, err := cbor.Marshal(map[string]any{
		"policyEngine": map[string]any{"use": "cedar"},
		"keyStorage":   map[string]any{"use": "disk", "disk": map[string]any{"path": "/srv"}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	snap, err := configsource.DecodeCBOR(data)
	if err != nil {
		t.Fatalf("DecodeCBOR: %v", err)
	}
	if _, ok := snap.Root.GetMap("policyEngine"); !ok {
		t.Fatalf("expected policyEngine object; got %#v", snap.Root)
	}
}

func TestDecodeYAML_AcceptsRealisticConfig(t *testing.T) {
	doc := strings.TrimSpace(`
policyEngine:
  use: cedar
keyStorage:
  use: disk
  disk:
    path: /srv
`)
	snap, err := configsource.DecodeYAML([]byte(doc))
	if err != nil {
		t.Fatalf("DecodeYAML: %v", err)
	}
	if _, ok := snap.Root.GetMap("policyEngine"); !ok {
		t.Fatalf("expected policyEngine object")
	}
}

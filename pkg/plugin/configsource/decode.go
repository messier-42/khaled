package configsource

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"gopkg.in/yaml.v3"

	"github.com/messier-42/khaled/pkg/config"
)

// StrictCBORDec is the CBOR DecMode used by Config Source plugins to
// decode configurations provided as CBOR.
var StrictCBORDec = func() cbor.DecMode {
	m, err := cbor.DecOptions{
		MaxNestedLevels:  32,
		MaxArrayElements: 65536,
		MaxMapPairs:      65536,
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
	}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("configsource: build strict cbor dec mode: %v", err))
	}
	return m
}()

// DecodeCBOR decodes a config snapshot from a CBOR byte slice using
// StrictCBORDec.
func DecodeCBOR(data []byte) (config.Snapshot, error) {
	var raw any
	if err := StrictCBORDec.Unmarshal(data, &raw); err != nil {
		return config.Snapshot{}, err
	}
	return config.NewSnapshot(raw)
}

// DecodeYAML decodes a config snapshot from a YAML byte slice.
func DecodeYAML(data []byte) (config.Snapshot, error) {
	var raw any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return config.Snapshot{}, err
	}
	return config.NewSnapshot(raw)
}

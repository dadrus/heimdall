package config

import "github.com/goccy/go-json"

type Mechanism struct {
	ID     string          `koanf:"id"`
	Type   string          `koanf:"type"`
	Config MechanismConfig `koanf:"config"`
}

type MechanismConfig map[string]any

func (in *MechanismConfig) DeepCopyInto(out *MechanismConfig) {
	if in == nil {
		return
	}

	jsonStr, _ := json.Marshal(in)

	// we cannot do anything with an error here as
	// the interface implemented here doesn't support
	// error responses
	json.Unmarshal(jsonStr, out) //nolint:errcheck
}

package kubernetes

import (
	"github.com/mitchellh/mapstructure"
)

func decodeConfig(input any, output any) error {
	dec, err := mapstructure.NewDecoder(
		&mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
			),
			Result:      output,
			ErrorUnused: true,
		})
	if err != nil {
		return err
	}

	return dec.Decode(input)
}

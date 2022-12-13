package filesystem

import (
	"github.com/mitchellh/mapstructure"
)

func decodeConfig(input any, output any) error {
	dec, err := mapstructure.NewDecoder(
		&mapstructure.DecoderConfig{
			Result:      output,
			ErrorUnused: true,
		})
	if err != nil {
		return err
	}

	return dec.Decode(input)
}

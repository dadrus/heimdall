package rule

import (
	"github.com/mitchellh/mapstructure"
)

func DecodeConfig(input any, output any) error {
	dec, err := mapstructure.NewDecoder(
		&mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				decodeRuleMatcher,
			),
			Result:      output,
			ErrorUnused: true,
			TagName:     "json",
		})
	if err != nil {
		return err
	}

	return dec.Decode(input)
}

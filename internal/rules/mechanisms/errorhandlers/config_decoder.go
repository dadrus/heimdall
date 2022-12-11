package errorhandlers

import (
	"github.com/mitchellh/mapstructure"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/errorhandlers/matcher"
)

func decodeConfig(input any, output any) error {
	dec, err := mapstructure.NewDecoder(
		&mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				matcher.DecodeCIDRMatcherHookFunc(),
				matcher.DecodeErrorTypeMatcherHookFunc(),
				matcher.StringToURLHookFunc(),
			),
			Result:      output,
			ErrorUnused: true,
		})
	if err != nil {
		return err
	}

	return dec.Decode(input)
}

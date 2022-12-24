package errorhandlers

import (
	"github.com/mitchellh/mapstructure"

	"github.com/dadrus/heimdall/internal/rules/mechanisms/errorhandlers/matcher"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
)

func decodeConfig(input any, output any) error {
	dec, err := mapstructure.NewDecoder(
		&mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				matcher.DecodeCIDRMatcherHookFunc(),
				matcher.DecodeErrorTypeMatcherHookFunc(),
				template.DecodeTemplateHookFunc(),
			),
			Result:      output,
			ErrorUnused: true,
		})
	if err != nil {
		return err
	}

	return dec.Decode(input)
}

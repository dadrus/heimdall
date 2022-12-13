package authorizers

import (
	"github.com/mitchellh/mapstructure"

	"github.com/dadrus/heimdall/internal/endpoint"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
)

func decodeConfig(input any, output any) error {
	dec, err := mapstructure.NewDecoder(
		&mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				endpoint.DecodeAuthenticationStrategyHookFunc(),
				endpoint.DecodeEndpointHookFunc(),
				mapstructure.StringToTimeDurationHookFunc(),
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

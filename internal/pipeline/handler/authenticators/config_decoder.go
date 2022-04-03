package authenticators

import (
	"github.com/mitchellh/mapstructure"

	"github.com/dadrus/heimdall/internal/pipeline/endpoint"
	"github.com/dadrus/heimdall/internal/pipeline/handler/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/pipeline/oauth2"
)

func decodeConfig(input any, output any) error {
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			extractors.DecodeCompositeExtractStrategyHookFunc(),
			oauth2.DecodeScopesMatcherHookFunc(),
			endpoint.DecodeAuthenticationStrategyHookFunc(),
		),
		Result:      output,
		ErrorUnused: true,
	})

	if err != nil {
		return err
	}

	return dec.Decode(input)
}

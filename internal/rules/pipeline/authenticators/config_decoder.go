package authenticators

import (
	"github.com/dadrus/heimdall/internal/rules/pipeline/authenticators/extractors"
	"github.com/dadrus/heimdall/internal/rules/pipeline/oauth2"
	"github.com/mitchellh/mapstructure"

	"github.com/dadrus/heimdall/internal/endpoint"
	"github.com/dadrus/heimdall/internal/truststore"
)

func decodeConfig(input any, output any) error {
	dec, err := mapstructure.NewDecoder(
		&mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
				extractors.DecodeCompositeExtractStrategyHookFunc(),
				oauth2.DecodeScopesMatcherHookFunc(),
				endpoint.DecodeAuthenticationStrategyHookFunc(),
				truststore.DecodeTrustStoreHookFunc(),
			),
			Result:      output,
			ErrorUnused: true,
		})
	if err != nil {
		return err
	}

	return dec.Decode(input)
}

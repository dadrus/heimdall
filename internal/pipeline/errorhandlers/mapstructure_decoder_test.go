package errorhandlers

import (
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/testsupport"
)

func TestDecodeCIDRMatcherHookFunc(t *testing.T) {
	t.Parallel()

	type Type struct {
		Matcher CIDRMatcher `mapstructure:"cidr"`
	}

	rawConfig := []byte(`
cidr:
  - 10.10.20.0/16
  - 192.168.1.0/24
`)

	var typ Type

	dec, err := mapstructure.NewDecoder(
		&mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				DecodeCIDRMatcherHookFunc(),
			),
			Result:      &typ,
			ErrorUnused: true,
		})
	require.NoError(t, err)

	mapConfig, err := testsupport.DecodeTestConfig(rawConfig)
	require.NoError(t, err)

	err = dec.Decode(mapConfig)
	require.NoError(t, err)

	assert.True(t, typ.Matcher.Match("192.168.1.10"))
}

func TestDecodeErrorTypeMatcherHookFunc(t *testing.T) {
	t.Parallel()

	type Type struct {
		Matcher ErrorTypeMatcher `mapstructure:"error"`
	}

	rawConfig := []byte(`
error:
  - unauthorized
  - forbidden
  - internal_server_error
  - bad_argument
`)

	var typ Type

	dec, err := mapstructure.NewDecoder(
		&mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				DecodeErrorTypeMatcherHookFunc(),
			),
			Result:      &typ,
			ErrorUnused: true,
		})
	require.NoError(t, err)

	mapConfig, err := testsupport.DecodeTestConfig(rawConfig)
	require.NoError(t, err)

	err = dec.Decode(mapConfig)
	require.NoError(t, err)

	assert.True(t, typ.Matcher.Match(heimdall.ErrConfiguration))
	assert.False(t, typ.Matcher.Match(heimdall.ErrCommunication))
}

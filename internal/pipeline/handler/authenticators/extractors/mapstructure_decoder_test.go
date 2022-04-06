package extractors

import (
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestUnmarshalAuthenticationDataSourceFromValidYaml(t *testing.T) {
	t.Parallel()

	var (
		ces      CompositeExtractStrategy
		settings interface{}
	)

	config := `
- cookie: foo_cookie
  strip_prefix: cfoo
- header: foo_header
  strip_prefix: hfoo
- query_parameter: foo_qparam
  strip_prefix: qfoo
`

	err := yaml.Unmarshal([]byte(config), &settings)
	assert.NoError(t, err)

	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			DecodeCompositeExtractStrategyHookFunc(),
		),
		Result: &ces,
	})
	assert.NoError(t, err)

	err = dec.Decode(settings)
	assert.NoError(t, err)
	assert.Equal(t, 3, len(ces))

	ce, ok := ces[0].(*CookieValueExtractStrategy)
	require.True(t, ok)
	assert.Equal(t, "foo_cookie", ce.Name)

	he, ok := ces[1].(*HeaderValueExtractStrategy)
	require.True(t, ok)
	assert.Equal(t, "foo_header", he.Name)
	assert.Equal(t, "hfoo", he.Prefix)

	qe, ok := ces[2].(*QueryParameterExtractStrategy)
	require.True(t, ok)
	assert.Equal(t, "foo_qparam", qe.Name)
}

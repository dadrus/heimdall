package extractors

import (
	"testing"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalAuthenticationDataSourceFromValidYaml(t *testing.T) {
	t.Parallel()

	var (
		ces      CompositeExtractStrategy
		settings map[string]any
	)

	config := []byte(`
authentication_data_source:
  - cookie: foo_cookie
  - header: foo_header
    strip_prefix: hfoo
  - query_parameter: foo_qparam
  - body_parameter: foo_bparam
`)

	parser := koanf.New(".")

	err := parser.Load(rawbytes.Provider(config), yaml.Parser())
	require.NoError(t, err)

	settings = parser.All()

	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			DecodeCompositeExtractStrategyHookFunc(),
		),
		Result: &ces,
	})
	assert.NoError(t, err)

	err = dec.Decode(settings["authentication_data_source"])
	assert.NoError(t, err)
	assert.Equal(t, 4, len(ces))

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

	be, ok := ces[3].(*BodyParameterExtractStrategy)
	require.True(t, ok)
	assert.Equal(t, "foo_bparam", be.Name)
}

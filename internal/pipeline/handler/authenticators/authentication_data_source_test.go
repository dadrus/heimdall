package authenticators

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/dadrus/heimdall/internal/pipeline/handler/authenticators/extractors"
)

func TestUnmarshalAuthenticationDataSourceFromValidYaml(t *testing.T) {
	t.Parallel()

	var as authenticationDataSource

	config := `
- cookie: foo_cookie
  strip_prefix: cfoo
- header: foo_header
  strip_prefix: hfoo
- query_parameter: foo_qparam
  strip_prefix: qfoo
- form_parameter: foo_fparam
  strip_prefix: ffoo
`

	err := yaml.Unmarshal([]byte(config), &as)
	assert.NoError(t, err)

	assert.NotNil(t, as.es)

	es, ok := as.es.(extractors.CompositeExtractStrategy)
	require.True(t, ok)
	assert.Equal(t, 4, len(es))

	ce, ok := es[0].(*extractors.CookieValueExtractStrategy)
	require.True(t, ok)
	assert.Equal(t, "foo_cookie", ce.Name)
	assert.Equal(t, "cfoo", ce.Prefix)

	he, ok := es[1].(*extractors.HeaderValueExtractStrategy)
	require.True(t, ok)
	assert.Equal(t, "foo_header", he.Name)
	assert.Equal(t, "hfoo", he.Prefix)

	qe, ok := es[2].(*extractors.QueryParameterExtractStrategy)
	require.True(t, ok)
	assert.Equal(t, "foo_qparam", qe.Name)
	assert.Equal(t, "qfoo", qe.Prefix)

	fe, ok := es[3].(*extractors.FormParameterExtractStrategy)
	require.True(t, ok)
	assert.Equal(t, "foo_fparam", fe.Name)
	assert.Equal(t, "ffoo", fe.Prefix)
}

func TestUnmarshalAuthenticationDataSourceFromEmptyYaml(t *testing.T) {
	t.Parallel()

	var as authenticationDataSource

	err := yaml.Unmarshal([]byte{}, &as)
	assert.NoError(t, err)

	assert.Nil(t, as.es)
}

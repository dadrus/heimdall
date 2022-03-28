package authenticators

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"gopkg.in/yaml.v2"

	"github.com/dadrus/heimdall/internal/pipeline/handler/authenticators/extractors"
)

func TestUnmarshalAuthenticationDataSourceFromValidYaml(t *testing.T) {
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

	s, err := as.Strategy()
	assert.NoError(t, err)
	assert.IsType(t, extractors.CompositeExtractStrategy{}, s)

	es := s.(extractors.CompositeExtractStrategy)
	assert.Equal(t, 4, len(es))

	assert.IsType(t, &extractors.CookieValueExtractStrategy{}, es[0])
	ce := es[0].(*extractors.CookieValueExtractStrategy)
	assert.Equal(t, "foo_cookie", ce.Name)
	assert.Equal(t, "cfoo", ce.Prefix)

	assert.IsType(t, &extractors.HeaderValueExtractStrategy{}, es[1])
	he := es[1].(*extractors.HeaderValueExtractStrategy)
	assert.Equal(t, "foo_header", he.Name)
	assert.Equal(t, "hfoo", he.Prefix)

	assert.IsType(t, &extractors.QueryParameterExtractStrategy{}, es[2])
	qe := es[2].(*extractors.QueryParameterExtractStrategy)
	assert.Equal(t, "foo_qparam", qe.Name)
	assert.Equal(t, "qfoo", qe.Prefix)

	assert.IsType(t, &extractors.FormParameterExtractStrategy{}, es[3])
	fe := es[3].(*extractors.FormParameterExtractStrategy)
	assert.Equal(t, "foo_fparam", fe.Name)
	assert.Equal(t, "ffoo", fe.Prefix)
}

func TestUnmarshalAuthenticationDataSourceFromEmptyYaml(t *testing.T) {
	var as authenticationDataSource

	err := yaml.Unmarshal([]byte{}, &as)
	assert.NoError(t, err)

	_, err = as.Strategy()
	assert.Error(t, err)
}

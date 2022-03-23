package authenticators

import (
	"encoding/json"
	"testing"

	"github.com/dadrus/heimdall/pipeline"
	"github.com/stretchr/testify/assert"
)

func TestCreateAnonymousAuthenticatorFromJsonConfig(t *testing.T) {
	// WHEN
	a, err := newAnonymousAuthenticator(json.RawMessage(`{"subject":"bla"}`))

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, "bla", a.Subject)
}

func TestAuthenticateWithAnonymousAuthenticatorWithDefaultSubjectId(t *testing.T) {
	// GIVEN
	a := anonymousAuthenticator{}
	sc := pipeline.SubjectContext{}

	// WHEN
	err := a.Authenticate(nil, nil, &sc)

	// THEN
	assert.NoError(t, err)
	assert.Empty(t, sc.Header)
	assert.NotNil(t, sc.Subject)
	assert.Equal(t, "anonymous", sc.Subject.Id)
}

func TestAuthenticateWithAnonymousAuthenticatorWithCustomSubjectId(t *testing.T) {
	// GIVEN
	subjectId := "anon"
	a := anonymousAuthenticator{Subject: subjectId}
	sc := pipeline.SubjectContext{}

	// WHEN
	err := a.Authenticate(nil, nil, &sc)

	// THEN
	assert.NoError(t, err)
	assert.Empty(t, sc.Header)
	assert.NotNil(t, sc.Subject)
	assert.Equal(t, subjectId, sc.Subject.Id)
}

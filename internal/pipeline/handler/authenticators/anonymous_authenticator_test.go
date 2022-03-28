package authenticators

import (
	"testing"

	"github.com/dadrus/heimdall/internal/errorsx"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/stretchr/testify/assert"
)

func TestCreateAnonymousAuthenticatorFromYaml(t *testing.T) {
	// WHEN
	a, err := NewAnonymousAuthenticatorFromYAML([]byte("subject: anon"))

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, "anon", a.Subject)
}

func TestCreateAnonymousAuthenticatorFromPrototypeGivenEmptyConfig(t *testing.T) {
	// GIVEN
	p, err := NewAnonymousAuthenticatorFromYAML([]byte("subject: anon"))
	assert.NoError(t, err)

	// WHEN
	a, err := p.WithConfig([]byte{})

	// THEN
	assert.NoError(t, err)

	// prototype and "created" authenticator are same
	assert.Equal(t, p, a)
}

func TestCreateAnonymousAuthenticatorFromPrototypeGivenValidConfig(t *testing.T) {
	// GIVEN
	p, err := NewAnonymousAuthenticatorFromYAML([]byte("subject: anon"))
	assert.NoError(t, err)

	// WHEN
	a, err := p.WithConfig([]byte("subject: foo"))

	// THEN
	assert.NoError(t, err)
	// prototype and "created" authenticator are different
	assert.NotEqual(t, p, a)
	assert.IsType(t, &anonymousAuthenticator{}, a)
	aa := a.(*anonymousAuthenticator)
	assert.Equal(t, "foo", aa.Subject)
}

func TestCreateAnonymousAuthenticatorFromPrototypeGivenInvalidConfig(t *testing.T) {
	// GIVEN
	p, err := NewAnonymousAuthenticatorFromYAML([]byte("subject: anon"))
	assert.NoError(t, err)

	// WHEN
	_, err = p.WithConfig([]byte("foo: bar"))

	// THEN
	assert.Error(t, err)
	assert.IsType(t, &errorsx.ArgumentError{}, err)
}

func TestAuthenticateWithAnonymousAuthenticatorWithCustomSubjectId(t *testing.T) {
	// GIVEN
	subjectId := "anon"
	a := anonymousAuthenticator{Subject: subjectId}
	sc := heimdall.SubjectContext{}

	// WHEN
	err := a.Authenticate(nil, nil, &sc)

	// THEN
	assert.NoError(t, err)
	assert.Empty(t, sc.Header)
	assert.NotNil(t, sc.Subject)
	assert.Equal(t, subjectId, sc.Subject.Id)
}

func TestAuthenticateWithAnonymousAuthenticatorWithDefaultSubjectId(t *testing.T) {
	// GIVEN
	a, err := NewAnonymousAuthenticatorFromYAML([]byte{})
	assert.NoError(t, err)
	sc := heimdall.SubjectContext{}

	// WHEN
	err = a.Authenticate(nil, nil, &sc)

	// THEN
	assert.NoError(t, err)
	assert.Empty(t, sc.Header)
	assert.NotNil(t, sc.Subject)
	assert.Equal(t, "anonymous", sc.Subject.Id)
}

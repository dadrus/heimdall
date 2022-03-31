package authenticators

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/errorsx"
	"github.com/dadrus/heimdall/internal/heimdall"
)

func TestCreateAnonymousAuthenticatorFromValidYaml(t *testing.T) {
	t.Parallel()
	// WHEN
	a, err := NewAnonymousAuthenticatorFromYAML([]byte("subject: anon"))

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, "anon", a.Subject)
}

func TestCreateAnonymousAuthenticatorFromInvalidYaml(t *testing.T) {
	t.Parallel()
	// WHEN
	_, err := NewAnonymousAuthenticatorFromYAML([]byte("foo: bar"))

	// THEN
	assert.Error(t, err)
	assert.IsType(t, &errorsx.ArgumentError{}, err)
}

func TestCreateAnonymousAuthenticatorFromPrototypeGivenEmptyConfig(t *testing.T) {
	t.Parallel()
	// GIVEN
	prototype, err := NewAnonymousAuthenticatorFromYAML([]byte("subject: anon"))
	assert.NoError(t, err)

	// WHEN
	auth, err := prototype.WithConfig([]byte{})

	// THEN
	assert.NoError(t, err)

	// prototype and "created" authenticator are same
	assert.Equal(t, prototype, auth)
}

func TestCreateAnonymousAuthenticatorFromPrototypeGivenValidConfig(t *testing.T) {
	t.Parallel()
	// GIVEN
	prototype, err := NewAnonymousAuthenticatorFromYAML([]byte("subject: anon"))
	assert.NoError(t, err)

	// WHEN
	auth, err := prototype.WithConfig([]byte("subject: foo"))

	// THEN
	assert.NoError(t, err)
	// prototype and "created" authenticator are different
	assert.NotEqual(t, prototype, auth)
	aa, ok := auth.(*anonymousAuthenticator)
	require.True(t, ok)
	assert.Equal(t, "foo", aa.Subject)
}

func TestCreateAnonymousAuthenticatorFromPrototypeGivenInvalidConfig(t *testing.T) {
	t.Parallel()
	// GIVEN
	prototype, err := NewAnonymousAuthenticatorFromYAML([]byte("subject: anon"))
	assert.NoError(t, err)

	// WHEN
	_, err = prototype.WithConfig([]byte("foo: bar"))

	// THEN
	assert.Error(t, err)
	assert.IsType(t, &errorsx.ArgumentError{}, err)
}

func TestAuthenticateWithAnonymousAuthenticatorWithCustomSubjectId(t *testing.T) {
	t.Parallel()
	// GIVEN
	subjectID := "anon"
	a := anonymousAuthenticator{Subject: subjectID}
	sc := heimdall.SubjectContext{}

	// WHEN
	err := a.Authenticate(nil, nil, &sc)

	// THEN
	assert.NoError(t, err)
	assert.Empty(t, sc.Header)
	assert.NotNil(t, sc.Subject)
	assert.Equal(t, subjectID, sc.Subject.ID)
}

func TestAuthenticateWithAnonymousAuthenticatorWithDefaultSubjectId(t *testing.T) {
	t.Parallel()
	// GIVEN
	auth, err := NewAnonymousAuthenticatorFromYAML([]byte{})
	assert.NoError(t, err)

	sc := heimdall.SubjectContext{}

	// WHEN
	err = auth.Authenticate(nil, nil, &sc)

	// THEN
	assert.NoError(t, err)
	assert.Empty(t, sc.Header)
	assert.NotNil(t, sc.Subject)
	assert.Equal(t, "anonymous", sc.Subject.ID)
}

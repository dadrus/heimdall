package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExpectationValidate(t *testing.T) {
	t.Parallel()

	// GIVEN
	exp1 := Expectation{}
	exp2 := Expectation{TrustedIssuers: []string{"foo"}}

	// WHEN
	err1 := exp1.Validate()
	err2 := exp2.Validate()

	// THEN
	assert.Error(t, err1)
	assert.NoError(t, err2)
}

func TestExpectationIsAlgorithmAllowed(t *testing.T) {
	t.Parallel()

	// GIVEN
	exp1 := Expectation{}
	exp2 := Expectation{AllowedAlgorithms: []string{"foo"}}

	// THEN
	assert.False(t, exp1.IsAlgorithmAllowed("foo"))
	assert.False(t, exp1.IsAlgorithmAllowed("bar"))

	assert.True(t, exp2.IsAlgorithmAllowed("foo"))
	assert.False(t, exp2.IsAlgorithmAllowed("bar"))
}

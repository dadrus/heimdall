package endpoint

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApplyBasicAuthStrategy(t *testing.T) {
	t.Parallel()

	// GIVEN
	user := "Foo"
	password := "Bar"
	expectedValue := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
	req := &http.Request{Header: http.Header{}}
	s := BasicAuthStrategy{User: user, Password: password}

	// WHEN
	err := s.Apply(nil, req)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, expectedValue, req.Header.Get("Authorization"))
}

func TestBasicAuthStrategyHash(t *testing.T) {
	// GIVEN
	s1 := &BasicAuthStrategy{User: "Foo", Password: "Bar"}
	s2 := &BasicAuthStrategy{User: "Foo", Password: "Baz"}

	// WHEN
	hash1 := s1.Hash()
	hash2 := s2.Hash()

	// THEN
	assert.NotEmpty(t, hash1)
	assert.NotEmpty(t, hash2)
	assert.NotEqual(t, hash1, hash2)
}

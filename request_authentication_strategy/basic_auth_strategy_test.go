package request_authentication_strategy

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApplyBasicAuthStrategy(t *testing.T) {
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

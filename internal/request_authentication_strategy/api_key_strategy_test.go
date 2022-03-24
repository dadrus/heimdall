package request_authentication_strategy

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApplyApiKeyStrategyOnHeader(t *testing.T) {
	// GIVEN
	name := "Foo"
	value := "Bar"
	req := &http.Request{Header: http.Header{}}
	s := ApiKeyStrategy{Name: name, Value: value, In: "header"}

	// WHEN
	err := s.Apply(nil, req)

	// THEN
	assert.NoError(t, err)
	assert.Equal(t, value, req.Header.Get(name))
}

func TestApplyApiKeyStrategyOnCookie(t *testing.T) {
	// GIVEN
	name := "Foo"
	value := "Bar"
	req := &http.Request{Header: http.Header{}}
	s := ApiKeyStrategy{Name: name, Value: value, In: "cookie"}

	// WHEN
	err := s.Apply(nil, req)

	// THEN
	assert.NoError(t, err)

	cookie, err := req.Cookie(name)
	assert.NoError(t, err)
	assert.Equal(t, value, cookie.Value)
}

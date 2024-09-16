package keyholder

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
)

type testKeyHolder []jose.JSONWebKey

func (t testKeyHolder) Keys() []jose.JSONWebKey { return t }

func TestRegistryKeys(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc        string
		keyHolder []KeyHolder
		assert    func(t *testing.T, keys []jose.JSONWebKey)
	}{
		{
			uc: "no key holders",
			assert: func(t *testing.T, keys []jose.JSONWebKey) {
				t.Helper()

				assert.Empty(t, keys)
			},
		},
		{
			uc:        "key holder without keys",
			keyHolder: []KeyHolder{testKeyHolder{}},
			assert: func(t *testing.T, keys []jose.JSONWebKey) {
				t.Helper()

				assert.Empty(t, keys)
			},
		},
		{
			uc:        "key holder with one key",
			keyHolder: []KeyHolder{testKeyHolder{{KeyID: "test-1"}}},
			assert: func(t *testing.T, keys []jose.JSONWebKey) {
				t.Helper()

				assert.Equal(t, []jose.JSONWebKey{{KeyID: "test-1"}}, keys)
			},
		},
		{
			uc:        "key holder with multiple keys",
			keyHolder: []KeyHolder{testKeyHolder{{KeyID: "test-1"}, {KeyID: "test-2"}}},
			assert: func(t *testing.T, keys []jose.JSONWebKey) {
				t.Helper()

				assert.Equal(t, []jose.JSONWebKey{{KeyID: "test-1"}, {KeyID: "test-2"}}, keys)
			},
		},
		{
			uc: "multiple key holders, one with single key, one with multiple keys and one without keys",
			keyHolder: []KeyHolder{
				testKeyHolder{{KeyID: "test-1"}, {KeyID: "test-2"}},
				testKeyHolder{},
				testKeyHolder{{KeyID: "test-3"}},
			},
			assert: func(t *testing.T, keys []jose.JSONWebKey) {
				t.Helper()

				assert.Equal(t, []jose.JSONWebKey{{KeyID: "test-1"}, {KeyID: "test-2"}, {KeyID: "test-3"}}, keys)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			// GIVEN
			reg := newRegistry()

			// WHEN
			for _, kh := range tc.keyHolder {
				reg.AddKeyHolder(kh)
			}

			// THEN
			tc.assert(t, reg.Keys())
		})
	}
}

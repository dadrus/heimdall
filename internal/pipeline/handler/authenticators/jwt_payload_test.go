package authenticators

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJwtPayloadIssuer(t *testing.T) {
	for _, tc := range []struct {
		uc        string
		configure func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter)
		assert    func(t *testing.T, err error)
	}{
		{
			uc:        "token without issuer",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {},
			assert: func(t *testing.T, err error) {
				assert.Error(t, err)
			},
		},
		{
			uc: "token with issuer",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				(*jp)["iss"] = "foo"
				ma.On("AssertIssuer", "foo").Return(nil)
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			m := &MockClaimAsserter{}
			jp := jwtPayload{}

			tc.configure(t, &jp, m)

			// WHEN
			err := jp.checkIssuer(m)

			// THEN
			tc.assert(t, err)
			m.AssertExpectations(t)
		})
	}
}

func TestJwtPayloadAudience(t *testing.T) {
	for _, tc := range []struct {
		uc        string
		configure func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter)
		assert    func(t *testing.T, err error)
	}{
		{
			uc: "aud claim is expected and present as string with single value",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				(*jp)["aud"] = "foo"
				ma.On("AssertAudience", []string{"foo"}).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			uc: "aud claim is expected and present as string with multiple values",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				(*jp)["aud"] = "foo bar"
				ma.On("AssertAudience", []string{"foo", "bar"}).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			uc: "aud claim is expected and present as array with single value",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				(*jp)["aud"] = []string{"foo"}
				ma.On("AssertAudience", []string{"foo"}).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			uc: "aud claim is expected and present as array with multiple values",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				(*jp)["aud"] = []string{"foo", "bar"}
				ma.On("AssertAudience", []string{"foo", "bar"}).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			uc: "aud claim is expected but not present",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				ma.On("AssertAudience", []string{}).Return(errors.New("no aud claim present"))
			},
			assert: func(t *testing.T, err error) {
				assert.Error(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			m := &MockClaimAsserter{}
			jp := jwtPayload{}

			tc.configure(t, &jp, m)

			// WHEN
			err := jp.checkAudience(m)

			// THEN
			tc.assert(t, err)
			m.AssertExpectations(t)
		})
	}
}

func TestJwtPayloadTokenId(t *testing.T) {
	for _, tc := range []struct {
		uc        string
		configure func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter)
		assert    func(t *testing.T, err error)
	}{
		{
			uc:        "token without jti",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {},
			assert: func(t *testing.T, err error) {
				assert.Error(t, err)
			},
		},
		{
			uc: "token with jti",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				(*jp)["jti"] = "foo"
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			m := &MockClaimAsserter{}
			jp := jwtPayload{}

			tc.configure(t, &jp, m)

			// WHEN
			err := jp.checkTokenId()

			// THEN
			tc.assert(t, err)
			m.AssertExpectations(t)
		})
	}
}

func TestJwtPayloadScope(t *testing.T) {
	for _, tc := range []struct {
		uc        string
		configure func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter)
		assert    func(t *testing.T, err error)
	}{
		{
			uc: "scp claim present as string with single value",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				(*jp)["scp"] = "foo"
				ma.On("AssertScopes", []string{"foo"}).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			uc: "scp claim present as string with multiple values",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				(*jp)["scp"] = "foo bar"
				ma.On("AssertScopes", []string{"foo", "bar"}).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			uc: "scp claim as array with single value",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				(*jp)["scp"] = []string{"foo"}
				ma.On("AssertScopes", []string{"foo"}).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			uc: "scp claim present as array with multiple values",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				(*jp)["scp"] = []string{"foo", "bar"}
				ma.On("AssertScopes", []string{"foo", "bar"}).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			uc: "scope claim present as string with single value",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				(*jp)["scope"] = "foo"
				ma.On("AssertScopes", []string{"foo"}).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			uc: "scope claim present as string with multiple values",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				(*jp)["scope"] = "foo bar"
				ma.On("AssertScopes", []string{"foo", "bar"}).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			uc: "scope claim as array with single value",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				(*jp)["scope"] = []string{"foo"}
				ma.On("AssertScopes", []string{"foo"}).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			uc: "scope claim present as array with multiple values",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				(*jp)["scope"] = []string{"foo", "bar"}
				ma.On("AssertScopes", []string{"foo", "bar"}).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			m := &MockClaimAsserter{}
			jp := jwtPayload{}

			tc.configure(t, &jp, m)

			// WHEN
			err := jp.checkScopes(m)

			// THEN
			tc.assert(t, err)
			m.AssertExpectations(t)
		})
	}
}

func TestJwtPayloadValidity(t *testing.T) {
	// GIVEN
	nbf := int64(2)
	exp := int64(3)

	m := &MockClaimAsserter{}
	m.On("AssertValidity", nbf, exp).Return(nil)

	jp := jwtPayload{"nbf": nbf, "exp": exp}

	// WHEN
	err := jp.checkTimeValidity(m)

	// THEN
	assert.NoError(t, err)
	m.AssertExpectations(t)
}

func TestJwtPayloadVerify(t *testing.T) {
	for _, tc := range []struct {
		uc        string
		configure func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter)
		assert    func(t *testing.T, err error)
	}{
		{
			uc: "no errors raised by asserter",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				(*jp)["iss"] = "foo"
				(*jp)["jti"] = "foobar"
				ma.On("AssertIssuer", "foo").Return(nil)
				ma.On("AssertAudience", []string{}).Return(nil)
				ma.On("AssertScopes", []string{}).Return(nil)
				ma.On("AssertValidity", int64(-1), int64(-1)).Return(nil)
			},
			assert: func(t *testing.T, err error) { assert.NoError(t, err) },
		},
		{
			uc: "jti is missing",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				(*jp)["iss"] = "foo"
				ma.On("AssertIssuer", "foo").Return(nil)
				ma.On("AssertAudience", []string{}).Return(nil)
				ma.On("AssertScopes", []string{}).Return(nil)
			},
			assert: func(t *testing.T, err error) { assert.Error(t, err) },
		},
		{
			uc:        "missing iss claim",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {},
			assert:    func(t *testing.T, err error) { assert.Error(t, err) },
		},
		{
			uc: "audience verification raises error",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				(*jp)["iss"] = "foo"
				(*jp)["jti"] = "foobar"
				ma.On("AssertIssuer", "foo").Return(nil)
				ma.On("AssertAudience", []string{}).Return(errors.New("error"))
			},
			assert: func(t *testing.T, err error) { assert.Error(t, err) },
		},
		{
			uc: "scopes verification raises error",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				(*jp)["iss"] = "foo"
				(*jp)["jti"] = "foobar"
				ma.On("AssertIssuer", "foo").Return(nil)
				ma.On("AssertAudience", []string{}).Return(nil)
				ma.On("AssertScopes", []string{}).Return(errors.New("error"))
			},
			assert: func(t *testing.T, err error) { assert.Error(t, err) },
		},
		{
			uc: "validity verification raises error",
			configure: func(t *testing.T, jp *jwtPayload, ma *MockClaimAsserter) {
				(*jp)["iss"] = "foo"
				(*jp)["jti"] = "foobar"
				ma.On("AssertIssuer", "foo").Return(nil)
				ma.On("AssertAudience", []string{}).Return(nil)
				ma.On("AssertScopes", []string{}).Return(nil)
				ma.On("AssertValidity", int64(-1), int64(-1)).Return(errors.New("error"))
			},
			assert: func(t *testing.T, err error) { assert.Error(t, err) },
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			m := &MockClaimAsserter{}
			jp := jwtPayload{}

			tc.configure(t, &jp, m)

			// WHEN
			err := jp.Verify(m)

			// THEN
			tc.assert(t, err)
			m.AssertExpectations(t)
		})
	}
}

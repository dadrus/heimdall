package authenticators

import (
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"testing"

	"github.com/dadrus/heimdall/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSuccessfulExecutionOfAuthenticationDataAuthenticator(t *testing.T) {
	sc := &pipeline.SubjectContext{}
	sub := &pipeline.Subject{Id: "bar"}
	ctx := context.Background()
	eResp := json.RawMessage("foo")
	authDataVal := "foobar"

	e := &MockEndpoint{}
	e.On("SendRequest", mock.Anything, mock.MatchedBy(func(r io.Reader) bool {
		val, _ := ioutil.ReadAll(r)
		return string(val) == authDataVal
	}),
	).Return(eResp, nil)

	se := &MockSubjectExtractor{}
	se.On("GetSubject", eResp).Return(sub, nil)

	adg := &MockAuthDataGetter{}
	adg.On("GetAuthData", mock.Anything).Return(authDataVal, nil)

	a := AuthenticationDataAuthenticator{
		Endpoint:         e,
		SubjectExtractor: se,
		AuthDataGetter:   adg,
	}

	err := a.Authenticate(ctx, nil, sc)
	assert.NoError(t, err)
	assert.Equal(t, sub, sc.Subject)

	e.AssertExpectations(t)
	se.AssertExpectations(t)
	adg.AssertExpectations(t)
}

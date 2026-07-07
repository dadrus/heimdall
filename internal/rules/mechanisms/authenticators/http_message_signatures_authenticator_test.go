// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package authenticators

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/dadrus/httpsig"
	"github.com/inhies/go-bytesize"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/handler/requestcontext"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/validation"
)

func TestHTTPMessageSignaturesAuthenticatorExecute(t *testing.T) {
	t.Parallel()

	privateKey := newTestEd25519PrivateKey(t)
	auth := newTestHTTPMessageSignaturesAuthenticator(t, privateKey, true)
	req := newSignedHMSRequest(t, privateKey)

	ctx := requestcontext.New()
	ctx.Init(req)
	t.Cleanup(ctx.Reset)

	sub := make(pipeline.Subject)
	err := auth.Execute(ctx, sub)

	require.NoError(t, err)
	require.Contains(t, sub, DefaultPrincipalName)
	assert.Equal(t, "test-key", sub[DefaultPrincipalName].ID)
	assert.Equal(t, "test-key", sub[DefaultPrincipalName].Attributes["key_id"])
}

func TestHTTPMessageSignaturesAuthenticatorExecuteWithContentDigest(t *testing.T) {
	t.Parallel()

	body := []byte(`{"message":"hello"}`)
	privateKey := newTestEd25519PrivateKey(t)
	auth := newTestHTTPMessageSignaturesAuthenticatorWithComponents(
		t,
		privateKey,
		true,
		[]string{"@method", "@authority", "@path", "content-digest", "content-length", "content-type"},
	)
	req := newSignedHMSRequestWithBody(t, privateKey, body)

	ctx := requestcontext.New()
	ctx.Init(req)
	t.Cleanup(ctx.Reset)

	originalMethod := req.Method
	originalURL := req.URL.String()
	originalHost := req.Host

	err := auth.Execute(ctx, make(pipeline.Subject))

	require.NoError(t, err)
	assert.Equal(t, originalMethod, req.Method)
	assert.Equal(t, originalURL, req.URL.String())
	assert.Equal(t, originalHost, req.Host)

	restoredBody, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, body, restoredBody)
}

func TestHTTPMessageSignaturesAuthenticatorRejectsBodyOverMaxBodySize(t *testing.T) {
	t.Parallel()

	body := bytes.Repeat([]byte("a"), 64*1024)
	privateKey := newTestEd25519PrivateKey(t)
	auth := newTestHTTPMessageSignaturesAuthenticatorWithComponents(
		t,
		privateKey,
		true,
		[]string{"@method", "@authority", "@path", "content-digest", "content-length", "content-type"},
	)
	auth.maxBodySize = 18 * bytesize.B
	req := newSignedHMSRequestWithBody(t, privateKey, body)
	bodyReader := &readLimitAssertingReadCloser{
		reader:  bytes.NewReader(body),
		maxRead: 19,
	}
	req.Body = bodyReader

	ctx := requestcontext.New()
	ctx.Init(req)
	t.Cleanup(ctx.Reset)

	err := auth.Execute(ctx, make(pipeline.Subject))

	require.Error(t, err)
	require.ErrorIs(t, err, pipeline.ErrAuthentication)
	require.ErrorContains(t, err, "exceeds configured maximum size")
	assert.LessOrEqual(t, bodyReader.read, int64(19))
}

func TestHTTPMessageSignaturesAuthenticatorUsesNormalizedAuthority(t *testing.T) {
	t.Parallel()

	privateKey := newTestEd25519PrivateKey(t)
	auth := newTestHTTPMessageSignaturesAuthenticator(t, privateKey, true)
	req := newSignedHMSRequestForAuthority(t, privateKey, "api.example.test")
	req.Host = "heimdall.internal"
	req.Header.Set("X-Forwarded-Host", "api.example.test")

	ctx := requestcontext.New()
	ctx.Init(req)
	t.Cleanup(ctx.Reset)

	err := auth.Execute(ctx, make(pipeline.Subject))

	require.NoError(t, err)
}

func TestHTTPMessageSignaturesAuthenticatorExecuteWithMissingSignature(t *testing.T) {
	t.Parallel()

	auth, ctx := newUnsignedHMSExecution(t, true)

	err := auth.Execute(ctx, make(pipeline.Subject))

	require.Error(t, err)
	require.ErrorIs(t, err, pipeline.ErrAuthentication)

	response := pipeline.NewResponseError(err).Response()
	assert.Equal(t, http.StatusUnauthorized, response.Code)
	assert.Contains(t, response.Headers, "Accept-Signature")
	assert.NotEmpty(t, response.Headers["Accept-Signature"])
}

func TestHTTPMessageSignaturesAuthenticatorDecorateErrorResponseDisabled(t *testing.T) {
	t.Parallel()

	auth, ctx := newUnsignedHMSExecution(t, false)

	err := auth.Execute(ctx, make(pipeline.Subject))

	require.Error(t, err)

	response := pipeline.NewResponseError(err).Response()
	assert.NotEqual(t, http.StatusUnauthorized, response.Code)
	assert.NotContains(t, response.Headers, "Accept-Signature")
}

func TestHTTPMessageSignaturesAuthenticatorWithoutTagDoesNotNegotiate(t *testing.T) {
	t.Parallel()

	auth, ctx := newUnsignedHMSExecution(t, true)
	auth.tag = ""
	auth.validateAllSignatures = true

	err := auth.Execute(ctx, make(pipeline.Subject))

	require.Error(t, err)
	require.ErrorIs(t, err, pipeline.ErrAuthentication)

	response := pipeline.NewResponseError(err).Response()
	assert.NotEqual(t, http.StatusInternalServerError, response.Code)
	assert.NotContains(t, response.Headers, "Accept-Signature")
}

func TestNewHTTPMessageSignaturesAuthenticator(t *testing.T) {
	t.Parallel()

	auth := newTestHTTPMessageSignaturesAuthenticator(t, newTestEd25519PrivateKey(t), true)

	assert.Equal(t, AuthenticatorHTTPMessageSignatures, auth.Name())
	assert.Equal(t, AuthenticatorHTTPMessageSignatures, auth.ID())
	assert.Equal(t, AuthenticatorHTTPMessageSignatures, auth.Type())
	assert.Equal(t, DefaultPrincipalName, auth.PrincipalName())
	assert.False(t, auth.IsInsecure())
	assert.Equal(t, []string{"@method", "@authority", "@path"}, auth.requiredComponents)
	assert.Equal(t, "hms", auth.tag)
	assert.True(t, auth.errorSignalingEnabled)
}

func TestNewHTTPMessageSignaturesAuthenticatorWithoutTagRequiresValidateAllSignatures(t *testing.T) {
	t.Parallel()

	appCtx := newTestAppContext(t)
	mechanism, err := newHTTPMessageSignaturesAuthenticator(appCtx, AuthenticatorHTTPMessageSignatures, config.MechanismConfig{
		"key_store": map[string]any{
			"source":   "hms_keys",
			"selector": "clients",
		},
		"required_components":     []any{"@method", "@authority", "@path"},
		"validate_all_signatures": false,
	})

	require.Error(t, err)
	assert.Nil(t, mechanism)
	require.ErrorIs(t, err, pipeline.ErrConfiguration)
	assert.ErrorContains(t, err, "requires a tag")
}

func TestNewHTTPMessageSignaturesAuthenticatorRejectsHostRequiredComponent(t *testing.T) {
	t.Parallel()

	appCtx := newTestAppContext(t)
	mechanism, err := newHTTPMessageSignaturesAuthenticator(appCtx, AuthenticatorHTTPMessageSignatures, config.MechanismConfig{
		"key_store": map[string]any{
			"source":   "hms_keys",
			"selector": "clients",
		},
		"required_components": []any{"@method", "Host;sf", "@path"},
		"tag":                 "hms",
	})

	require.Error(t, err)
	assert.Nil(t, mechanism)
	require.ErrorIs(t, err, pipeline.ErrConfiguration)
	assert.ErrorContains(t, err, "requires @authority instead of host")
}

func TestToHTTPSigVerificationKeysRejectsAsymmetricSecretWithoutPrivateKey(t *testing.T) {
	t.Parallel()

	keys, err := toHTTPSigVerificationKeys([]secrets.Secret{
		secrettypes.NewAsymmetricKeySecret("test-key", "test-key", nil, nil),
	})

	require.Error(t, err)
	assert.Nil(t, keys)
	require.ErrorIs(t, err, pipeline.ErrConfiguration)
	assert.ErrorContains(t, err, "does not contain private key material")
}

func newTestEd25519PrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	return privateKey
}

func newUnsignedHMSExecution(
	t *testing.T,
	errorSignalingEnabled bool,
) (*httpMessageSignaturesAuthenticator, *requestcontext.RequestContext) {
	t.Helper()

	auth := newTestHTTPMessageSignaturesAuthenticator(t, newTestEd25519PrivateKey(t), errorSignalingEnabled)
	req := httptest.NewRequest(http.MethodGet, "https://api.example.test/foo", nil)
	ctx := requestcontext.New()
	ctx.Init(req)
	t.Cleanup(ctx.Reset)

	return auth, ctx
}

func newTestHTTPMessageSignaturesAuthenticator(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	errorSignalingEnabled bool,
) *httpMessageSignaturesAuthenticator {
	t.Helper()

	return newTestHTTPMessageSignaturesAuthenticatorWithComponents(
		t,
		privateKey,
		errorSignalingEnabled,
		[]string{"@method", "@authority", "@path"},
	)
}

func newTestHTTPMessageSignaturesAuthenticatorWithComponents(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	errorSignalingEnabled bool,
	requiredComponents []string,
) *httpMessageSignaturesAuthenticator {
	t.Helper()

	validator, err := validation.NewValidator()
	require.NoError(t, err)

	resolver := secretsmocks.NewResolverMock(t)
	handle := secretsmocks.NewSecretSetHandleMock(t)

	resolver.EXPECT().
		SecretSet(secrets.Reference{Source: "hms_keys", Selector: "clients"}).
		Return(handle, nil)

	handle.EXPECT().
		OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[[]secrets.Secret]) bool {
			err := cb(t.Context(), []secrets.Secret{
				secrettypes.NewAsymmetricKeySecret("test-key", "test-key", privateKey, nil),
			})
			require.NoError(t, err)

			return true
		}))

	appCtx := app.NewContextMock(t)
	appCtx.EXPECT().Logger().Return(log.Logger)
	appCtx.EXPECT().SecretResolver().Maybe().Return(resolver)
	appCtx.EXPECT().
		DecoderFactory().
		Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))

	rawComponents := make([]any, 0, len(requiredComponents))
	for _, component := range requiredComponents {
		rawComponents = append(rawComponents, component)
	}

	mechanism, err := newHTTPMessageSignaturesAuthenticator(appCtx, AuthenticatorHTTPMessageSignatures, config.MechanismConfig{
		"key_store": map[string]any{
			"source":   "hms_keys",
			"selector": "clients",
		},
		"required_components": rawComponents,
		"tag":                 "hms",
		"principal": map[string]any{
			"id": "key_id",
		},
		"error_signaling": map[string]any{
			"enabled": errorSignalingEnabled,
		},
	})
	require.NoError(t, err)

	auth, ok := mechanism.(*httpMessageSignaturesAuthenticator)
	require.True(t, ok)

	return auth
}

func newTestAppContext(t *testing.T) app.Context {
	t.Helper()

	validator, err := validation.NewValidator()
	require.NoError(t, err)

	appCtx := app.NewContextMock(t)
	appCtx.EXPECT().Logger().Return(log.Logger)
	appCtx.EXPECT().SecretResolver().Maybe().Return(secretsmocks.NewResolverMock(t))
	appCtx.EXPECT().
		DecoderFactory().
		Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))

	return appCtx
}

func newSignedHMSRequest(t *testing.T, privateKey ed25519.PrivateKey) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "https://api.example.test/foo", nil)

	signer, err := httpsig.NewSigner(
		httpsig.Key{KeyID: "test-key", Algorithm: httpsig.Ed25519, Key: privateKey},
		httpsig.WithComponents("@method", "@authority", "@path"),
		httpsig.WithTag("hms"),
	)
	require.NoError(t, err)

	headers, err := signer.Sign(httpsig.MessageFromRequest(req))
	require.NoError(t, err)

	req.Header = headers

	return req
}

func newSignedHMSRequestWithBody(t *testing.T, privateKey ed25519.PrivateKey, body []byte) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "https://api.example.test/foo", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))

	signer, err := httpsig.NewSigner(
		httpsig.Key{KeyID: "test-key", Algorithm: httpsig.Ed25519, Key: privateKey},
		httpsig.WithComponents("@method", "@authority", "@path", "content-digest", "content-length", "content-type"),
		httpsig.WithTag("hms"),
	)
	require.NoError(t, err)

	headers, err := signer.Sign(httpsig.MessageFromRequest(req))
	require.NoError(t, err)

	req.Header = headers
	req.Body = io.NopCloser(bytes.NewReader(body))

	return req
}

func newSignedHMSRequestForAuthority(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	authority string,
) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "https://heimdall.internal/foo", nil)
	msgURL := &url.URL{
		Scheme: "https",
		Host:   authority,
		Path:   "/foo",
	}

	signer, err := httpsig.NewSigner(
		httpsig.Key{KeyID: "test-key", Algorithm: httpsig.Ed25519, Key: privateKey},
		httpsig.WithComponents("@method", "@authority", "@path"),
		httpsig.WithTag("hms"),
	)
	require.NoError(t, err)

	headers, err := signer.Sign(&httpsig.Message{
		Context:   req.Context(),
		Method:    req.Method,
		Authority: authority,
		URL:       msgURL,
		Header:    req.Header.Clone(),
		Body:      func() (io.ReadCloser, error) { return http.NoBody, nil },
		IsRequest: true,
	})
	require.NoError(t, err)

	req.Header = headers

	return req
}

type readLimitAssertingReadCloser struct {
	reader  *bytes.Reader
	maxRead int64
	read    int64
}

func (r *readLimitAssertingReadCloser) Read(data []byte) (int, error) {
	if r.read >= r.maxRead {
		return 0, assert.AnError
	}

	remaining := r.maxRead - r.read
	if int64(len(data)) > remaining {
		data = data[:remaining]
	}

	n, err := r.reader.Read(data)
	r.read += int64(n)

	return n, err
}

func (*readLimitAssertingReadCloser) Close() error {
	return nil
}

// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
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

package rules

import (
	"errors"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/pipeline"
	heimdallmocks "github.com/dadrus/heimdall/internal/pipeline/mocks"
	"github.com/dadrus/heimdall/internal/rules/api/v1beta1"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
)

func TestRuleExecute(t *testing.T) {
	t.Parallel()

	falseValue := false
	trueValue := true

	for uc, tc := range map[string]struct {
		backend        *v1beta1.Backend
		slashHandling  v1beta1.EncodedSlashesHandling
		configureMocks func(
			t *testing.T,
			ctx *heimdallmocks.ContextMock,
			authenticator *heimdallmocks.StepMock,
			authorizer *heimdallmocks.StepMock,
			finalizer *heimdallmocks.StepMock,
			errHandler *heimdallmocks.StepMock,
		)
		assert func(t *testing.T, err error, backend rule.Backend, captures map[string]string)
	}{
		"authenticator fails, but error handler succeeds": {
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *heimdallmocks.StepMock,
				_ *heimdallmocks.StepMock, _ *heimdallmocks.StepMock,
				errHandler *heimdallmocks.StepMock,
			) {
				t.Helper()

				testErr := errors.New("test error")

				ctx.EXPECT().Request().Return(&pipeline.Request{URL: &pipeline.URL{}})
				ctx.EXPECT().SetError(testErr)

				authenticator.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(testErr)
				errHandler.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
			},
			assert: func(t *testing.T, err error, backend rule.Backend, _ map[string]string) {
				t.Helper()

				require.NoError(t, err)
				assert.Nil(t, backend)
			},
		},
		"authenticator fails, and error handler fails": {
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *heimdallmocks.StepMock,
				_ *heimdallmocks.StepMock, _ *heimdallmocks.StepMock,
				errHandler *heimdallmocks.StepMock,
			) {
				t.Helper()

				testErr := errors.New("test error")

				ctx.EXPECT().Request().Return(&pipeline.Request{URL: &pipeline.URL{}})
				ctx.EXPECT().SetError(testErr)

				authenticator.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(testErr)
				errHandler.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(errors.New("some error"))
			},
			assert: func(t *testing.T, err error, backend rule.Backend, _ map[string]string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "some error")
				assert.Nil(t, backend)
			},
		},
		"authenticator succeeds, authorizer fails, but error handler succeeds": {
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *heimdallmocks.StepMock,
				authorizer *heimdallmocks.StepMock, _ *heimdallmocks.StepMock,
				errHandler *heimdallmocks.StepMock,
			) {
				t.Helper()

				testErr := errors.New("test error")

				ctx.EXPECT().Request().Return(&pipeline.Request{URL: &pipeline.URL{}})
				ctx.EXPECT().SetError(testErr)

				authenticator.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
				authorizer.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(testErr)
				errHandler.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
			},
			assert: func(t *testing.T, err error, backend rule.Backend, _ map[string]string) {
				t.Helper()

				require.NoError(t, err)
				assert.Nil(t, backend)
			},
		},
		"authenticator succeeds, authorizer fails and error handler fails": {
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *heimdallmocks.StepMock,
				authorizer *heimdallmocks.StepMock, _ *heimdallmocks.StepMock,
				errHandler *heimdallmocks.StepMock,
			) {
				t.Helper()

				testErr := errors.New("test error")

				ctx.EXPECT().Request().Return(&pipeline.Request{URL: &pipeline.URL{}})
				ctx.EXPECT().SetError(testErr)

				authenticator.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
				authorizer.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(testErr)
				errHandler.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(errors.New("some error"))
			},
			assert: func(t *testing.T, err error, backend rule.Backend, _ map[string]string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "some error")
				assert.Nil(t, backend)
			},
		},
		"authenticator succeeds, authorizer succeeds, finalizer fails, but error handler succeeds": {
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *heimdallmocks.StepMock,
				authorizer *heimdallmocks.StepMock, finalizer *heimdallmocks.StepMock,
				errHandler *heimdallmocks.StepMock,
			) {
				t.Helper()

				testErr := errors.New("test error")

				ctx.EXPECT().Request().Return(&pipeline.Request{URL: &pipeline.URL{}})
				ctx.EXPECT().SetError(testErr)

				authenticator.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
				authorizer.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
				finalizer.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(testErr)
				errHandler.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
			},
			assert: func(t *testing.T, err error, backend rule.Backend, _ map[string]string) {
				t.Helper()

				require.NoError(t, err)
				assert.Nil(t, backend)
			},
		},
		"authenticator succeeds, authorizer succeeds, finalizer fails and error handler fails": {
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *heimdallmocks.StepMock,
				authorizer *heimdallmocks.StepMock, finalizer *heimdallmocks.StepMock,
				errHandler *heimdallmocks.StepMock,
			) {
				t.Helper()

				testErr := errors.New("test error")

				ctx.EXPECT().Request().Return(&pipeline.Request{URL: &pipeline.URL{}})
				ctx.EXPECT().SetError(testErr)

				authenticator.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
				authorizer.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
				finalizer.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(testErr)
				errHandler.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(errors.New("some error"))
			},
			assert: func(t *testing.T, err error, backend rule.Backend, _ map[string]string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "some error")
				assert.Nil(t, backend)
			},
		},
		"all handler succeed with disallowed urlencoded slashes": {
			slashHandling: v1beta1.EncodedSlashesOff,
			backend: &v1beta1.Backend{
				Host: "foo.bar",
			},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, _ *heimdallmocks.StepMock,
				_ *heimdallmocks.StepMock, _ *heimdallmocks.StepMock, _ *heimdallmocks.StepMock,
			) {
				t.Helper()

				targetURL, _ := url.Parse("http://foo.local/api%2Fv1/foo%5Bid%5D")
				ctx.EXPECT().Request().Return(&pipeline.Request{
					URL: &pipeline.URL{
						URL:      *targetURL,
						Captures: map[string]string{"first": "api%2Fv1", "second": "foo%5Bid%5D"},
					},
				})
			},
			assert: func(t *testing.T, err error, _ rule.Backend, _ map[string]string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, pipeline.ErrArgument)
				require.ErrorContains(t, err, "path contains encoded slash")
			},
		},
		"all handler succeed with urlencoded slashes on without urlencoded slash": {
			slashHandling: v1beta1.EncodedSlashesOn,
			backend: &v1beta1.Backend{
				Host: "foo.bar",
			},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *heimdallmocks.StepMock,
				authorizer *heimdallmocks.StepMock, finalizer *heimdallmocks.StepMock,
				_ *heimdallmocks.StepMock,
			) {
				t.Helper()

				authenticator.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
				authorizer.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
				finalizer.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)

				targetURL, _ := url.Parse("http://foo.local/api/v1/foo%5Bid%5D")
				ctx.EXPECT().Request().Return(&pipeline.Request{
					URL: &pipeline.URL{
						URL:      *targetURL,
						Captures: map[string]string{"first": "api", "second": "v1", "third": "foo%5Bid%5D"},
					},
				})
			},
			assert: func(t *testing.T, err error, backend rule.Backend, captures map[string]string) {
				t.Helper()

				require.NoError(t, err)

				expectedURL, _ := url.Parse("http://foo.bar/api/v1/foo%5Bid%5D")
				assert.Equal(t, expectedURL, backend.URL())
				assert.True(t, backend.ForwardHostHeader())

				assert.Equal(t, "api", captures["first"])
				assert.Equal(t, "v1", captures["second"])
				assert.Equal(t, "foo[id]", captures["third"])
			},
		},
		"all handler succeed with urlencoded slashes on with urlencoded slash": {
			slashHandling: v1beta1.EncodedSlashesOn,
			backend: &v1beta1.Backend{
				Host: "foo.bar",
			},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *heimdallmocks.StepMock,
				authorizer *heimdallmocks.StepMock, finalizer *heimdallmocks.StepMock,
				_ *heimdallmocks.StepMock,
			) {
				t.Helper()

				authenticator.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
				authorizer.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
				finalizer.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)

				targetURL, _ := url.Parse("http://foo.local/api%2Fv1/foo%5Bid%5D")
				ctx.EXPECT().Request().Return(&pipeline.Request{
					URL: &pipeline.URL{
						URL:      *targetURL,
						Captures: map[string]string{"first": "api%2Fv1", "second": "foo%5Bid%5D"},
					},
				})
			},
			assert: func(t *testing.T, err error, backend rule.Backend, captures map[string]string) {
				t.Helper()

				require.NoError(t, err)

				expectedURL, _ := url.Parse("http://foo.bar/api/v1/foo%5Bid%5D")
				assert.Equal(t, expectedURL, backend.URL())
				assert.True(t, backend.ForwardHostHeader())

				assert.Equal(t, "api/v1", captures["first"])
				assert.Equal(t, "foo[id]", captures["second"])
			},
		},
		"all handler succeed with urlencoded slashes on with urlencoded slash but without decoding it": {
			slashHandling: v1beta1.EncodedSlashesOnNoDecode,
			backend: &v1beta1.Backend{
				Host: "foo.bar",
			},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *heimdallmocks.StepMock,
				authorizer *heimdallmocks.StepMock, finalizer *heimdallmocks.StepMock,
				_ *heimdallmocks.StepMock,
			) {
				t.Helper()

				authenticator.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
				authorizer.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
				finalizer.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)

				targetURL, _ := url.Parse("http://foo.local/api%2Fv1/foo%5Bid%5D")
				ctx.EXPECT().Request().Return(&pipeline.Request{
					URL: &pipeline.URL{
						URL:      *targetURL,
						Captures: map[string]string{"first": "api%2Fv1", "second": "foo%5Bid%5D"},
					},
				})
			},
			assert: func(t *testing.T, err error, backend rule.Backend, captures map[string]string) {
				t.Helper()

				require.NoError(t, err)

				expectedURL, _ := url.Parse("http://foo.bar/api%2Fv1/foo%5Bid%5D")
				assert.Equal(t, expectedURL, backend.URL())
				assert.True(t, backend.ForwardHostHeader())

				assert.Equal(t, "api%2Fv1", captures["first"])
				assert.Equal(t, "foo[id]", captures["second"])
			},
		},
		"stripping path prefix": {
			backend: &v1beta1.Backend{
				Host:        "foo.bar",
				URLRewriter: &v1beta1.URLRewriter{PathPrefixToCut: "/api/v1"},
			},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *heimdallmocks.StepMock,
				authorizer *heimdallmocks.StepMock, finalizer *heimdallmocks.StepMock,
				_ *heimdallmocks.StepMock,
			) {
				t.Helper()

				authenticator.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
				authorizer.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
				finalizer.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)

				targetURL, _ := url.Parse("http://foo.local/api/v1/foo")
				ctx.EXPECT().Request().Return(&pipeline.Request{URL: &pipeline.URL{URL: *targetURL}})
			},
			assert: func(t *testing.T, err error, backend rule.Backend, _ map[string]string) {
				t.Helper()

				require.NoError(t, err)

				expectedURL, _ := url.Parse("http://foo.bar/foo")
				assert.Equal(t, expectedURL, backend.URL())
				assert.True(t, backend.ForwardHostHeader())
			},
		},
		"not forwarding Host header": {
			backend: &v1beta1.Backend{
				Host:              "foo.bar",
				ForwardHostHeader: &falseValue,
			},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *heimdallmocks.StepMock,
				authorizer *heimdallmocks.StepMock, finalizer *heimdallmocks.StepMock,
				_ *heimdallmocks.StepMock,
			) {
				t.Helper()

				authenticator.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
				authorizer.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
				finalizer.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)

				targetURL, _ := url.Parse("http://foo.local/api/v1/foo")
				ctx.EXPECT().Request().Return(&pipeline.Request{URL: &pipeline.URL{URL: *targetURL}})
			},
			assert: func(t *testing.T, err error, backend rule.Backend, _ map[string]string) {
				t.Helper()

				require.NoError(t, err)

				expectedURL, _ := url.Parse("http://foo.bar/api/v1/foo")
				assert.Equal(t, expectedURL, backend.URL())
				assert.False(t, backend.ForwardHostHeader())
			},
		},
		"explicitly forwarding Host header": {
			backend: &v1beta1.Backend{
				Host:              "foo.bar",
				ForwardHostHeader: &trueValue,
			},
			configureMocks: func(t *testing.T, ctx *heimdallmocks.ContextMock, authenticator *heimdallmocks.StepMock,
				authorizer *heimdallmocks.StepMock, finalizer *heimdallmocks.StepMock,
				_ *heimdallmocks.StepMock,
			) {
				t.Helper()

				authenticator.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
				authorizer.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)
				finalizer.EXPECT().Execute(ctx, mock.MatchedBy(
					func(sub pipeline.Subject) bool { return sub != nil },
				)).Return(nil)

				targetURL, _ := url.Parse("http://foo.local/api/v1/foo")
				ctx.EXPECT().Request().Return(&pipeline.Request{URL: &pipeline.URL{URL: *targetURL}})
			},
			assert: func(t *testing.T, err error, backend rule.Backend, _ map[string]string) {
				t.Helper()

				require.NoError(t, err)

				expectedURL, _ := url.Parse("http://foo.bar/api/v1/foo")
				assert.Equal(t, expectedURL, backend.URL())
				assert.True(t, backend.ForwardHostHeader())
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			ctx := heimdallmocks.NewContextMock(t)
			ctx.EXPECT().Context().Return(t.Context())

			authenticator := heimdallmocks.NewStepMock(t)
			authorizer := heimdallmocks.NewStepMock(t)
			finalizer := heimdallmocks.NewStepMock(t)
			errHandler := heimdallmocks.NewStepMock(t)

			rul := &ruleImpl{
				backend:         tc.backend,
				slashesHandling: x.IfThenElse(len(tc.slashHandling) != 0, tc.slashHandling, v1beta1.EncodedSlashesOff),
				sc:              stage{authenticator},
				sh:              stage{authorizer},
				fi:              stage{finalizer},
				eh:              stage{errHandler},
				subjectPool:     &sync.Pool{New: func() any { return make(pipeline.Subject, 4) }},
			}

			tc.configureMocks(t, ctx, authenticator, authorizer, finalizer, errHandler)

			// WHEN
			upstream, err := rul.Execute(ctx)

			// THEN
			tc.assert(t, err, upstream, ctx.Request().URL.Captures)
		})
	}
}

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

package authenticators

import (
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestCreateAnonymousAuthenticator(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config []byte
		assert func(t *testing.T, err error, auth *anonymousAuthenticator)
	}{
		"subject is set to anon": {
			config: []byte("subject: anon"),
			assert: func(t *testing.T, err error, auth *anonymousAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "anon", auth.Subject)
				assert.Equal(t, "subject is set to anon", auth.ID())
			},
		},
		"default subject": {
			config: nil,
			assert: func(t *testing.T, err error, auth *anonymousAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, "anonymous", auth.Subject)
				assert.Equal(t, "default subject", auth.ID())
			},
		},
		"unsupported attributes": {
			config: []byte("foo: bar"),
			assert: func(t *testing.T, err error, _ *anonymousAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			// WHEN
			auth, err := newAnonymousAuthenticator(appCtx, uc, conf)

			// THEN
			tc.assert(t, err, auth)
		})
	}
}

func TestCreateAnonymousAuthenticatorFromPrototype(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		prototypeConfig []byte
		config          []byte
		assert          func(t *testing.T, err error, prototype *anonymousAuthenticator, configured *anonymousAuthenticator)
	}{
		"no new configuration for the configured authenticator": {
			assert: func(t *testing.T, err error, prototype *anonymousAuthenticator, configured *anonymousAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
				assert.Equal(t, "anonymous", configured.Subject)
				assert.Equal(t, "no new configuration for the configured authenticator", configured.ID())
			},
		},
		"new subject for the configured authenticator": {
			prototypeConfig: []byte("subject: anon"),
			config:          []byte("subject: foo"),
			assert: func(t *testing.T, err error, prototype *anonymousAuthenticator, configured *anonymousAuthenticator) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.id, configured.id)
				assert.Equal(t, "new subject for the configured authenticator", configured.ID())
				assert.NotEqual(t, prototype.Subject, configured.Subject)
				assert.Equal(t, "anon", prototype.Subject)
				assert.Equal(t, "foo", configured.Subject)
			},
		},
		"malformed configured authenticator config": {
			config: []byte("foo: bar"),
			assert: func(t *testing.T, err error, _ *anonymousAuthenticator, _ *anonymousAuthenticator) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				assert.Contains(t, err.Error(), "failed decoding")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			pc, err := testsupport.DecodeTestConfig(tc.prototypeConfig)
			require.NoError(t, err)

			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			validator, err := validation.NewValidator()
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			prototype, err := newAnonymousAuthenticator(appCtx, uc, pc)
			require.NoError(t, err)

			// WHEN
			auth, err := prototype.WithConfig(conf)

			// THEN
			baa, ok := auth.(*anonymousAuthenticator)
			require.True(t, ok)

			tc.assert(t, err, prototype, baa)
		})
	}
}

func TestAnonymousAuthenticatorExecute(t *testing.T) {
	t.Parallel()

	// GIVEN
	subjectID := "anon"
	auth := anonymousAuthenticator{Subject: subjectID, id: "anon_auth"}

	ctx := mocks.NewRequestContextMock(t)
	ctx.EXPECT().Context().Return(t.Context())

	// WHEN
	sub, err := auth.Execute(ctx)

	// THEN
	require.NoError(t, err)
	assert.NotNil(t, sub)
	assert.Equal(t, subjectID, sub.ID)
	assert.Empty(t, sub.Attributes)
	assert.NotNil(t, sub.Attributes)
}

func TestAnonymousAuthenticatorIsInsecure(t *testing.T) {
	t.Parallel()

	// GIVEN
	auth := anonymousAuthenticator{}

	// WHEN & THEN
	require.True(t, auth.IsInsecure())
}

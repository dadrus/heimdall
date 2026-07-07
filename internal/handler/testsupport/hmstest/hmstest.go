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

package hmstest

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/url"
	"testing"

	"github.com/dadrus/httpsig"
	"github.com/inhies/go-bytesize"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/pipeline"
	_ "github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators" // registers authenticators
	_ "github.com/dadrus/heimdall/internal/rules/mechanisms/finalizers"     // registers finalizers
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/secrets"
	secretsmocks "github.com/dadrus/heimdall/internal/secrets/mocks"
	secrettypes "github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/validation"
)

const (
	KeyID    = "test-key"
	KeySet   = "hms_keys"
	Selector = "clients"
	Tag      = "hms"
)

func RequestWithDigestComponents() []string {
	return []string{
		"@method",
		"@authority",
		"@path",
		"content-digest",
		"content-length",
		"content-type",
	}
}

func NewEd25519PrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	return privateKey
}

func NewHTTPMessageSignaturesAuthenticatorStep(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	components []string,
) pipeline.Step {
	t.Helper()

	validator, err := validation.NewValidator()
	require.NoError(t, err)

	resolver := secretsmocks.NewResolverMock(t)
	handle := secretsmocks.NewSecretSetHandleMock(t)

	resolver.EXPECT().
		SecretSet(secrets.Reference{Source: KeySet, Selector: Selector}).
		Return(handle, nil)

	handle.EXPECT().
		OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[[]secrets.Secret]) bool {
			err := cb(t.Context(), []secrets.Secret{
				secrettypes.NewAsymmetricKeySecret(KeyID, KeyID, privateKey, nil),
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

	rawComponents := make([]any, 0, len(components))
	for _, component := range components {
		rawComponents = append(rawComponents, component)
	}

	mechanism, err := registry.Create(appCtx,
		types.KindAuthenticator,
		"http_message_signatures",
		"hms",
		config.MechanismConfig{
			"key_store": map[string]any{
				"source":   KeySet,
				"selector": Selector,
			},
			"required_components": rawComponents,
			"tag":                 Tag,
		})
	require.NoError(t, err)

	step, err := mechanism.CreateStep(resolver, types.StepDefinition{})
	require.NoError(t, err)

	return step
}

func NewHTTPMessageSignaturesFinalizerStep(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	components []string,
	maxBodySize ...bytesize.ByteSize,
) pipeline.Step {
	t.Helper()

	validator, err := validation.NewValidator()
	require.NoError(t, err)

	resolver := secretsmocks.NewResolverMock(t)
	handle := secretsmocks.NewSecretHandleMock(t)

	resolver.EXPECT().
		Secret(secrets.Reference{Source: KeySet, Selector: Selector}).
		Return(handle, nil)

	handle.EXPECT().
		OnUpdate(mock.MatchedBy(func(cb secrets.UpdateFunc[secrets.Secret]) bool {
			err := cb(t.Context(), secrettypes.NewAsymmetricKeySecret(KeyID, KeyID, privateKey, nil))
			require.NoError(t, err)

			return true
		}))

	appCtx := app.NewContextMock(t)
	appCtx.EXPECT().Logger().Return(log.Logger)
	appCtx.EXPECT().SecretResolver().Maybe().Return(resolver)
	appCtx.EXPECT().KeyRegistry().Maybe().Return(nil)
	appCtx.EXPECT().
		DecoderFactory().
		Return(encoding.NewDecoderFactory(encoding.ValidatorFunc(validator.ValidateStruct)))

	rawComponents := make([]any, 0, len(components))
	for _, component := range components {
		rawComponents = append(rawComponents, component)
	}

	rawConfig := config.MechanismConfig{
		"signer": map[string]any{
			"name": Tag,
			"secret": map[string]any{
				"source":   KeySet,
				"selector": Selector,
			},
		},
		"components": rawComponents,
		"ttl":        "30s",
	}

	if len(maxBodySize) != 0 {
		rawConfig["max_body_size"] = maxBodySize[0]
	}

	mechanism, err := registry.Create(appCtx,
		types.KindFinalizer,
		"http_message_signatures",
		"hms",
		rawConfig)
	require.NoError(t, err)

	step, err := mechanism.CreateStep(resolver, types.StepDefinition{})
	require.NoError(t, err)

	return step
}

func SignRequest(
	t *testing.T,
	req *http.Request,
	privateKey ed25519.PrivateKey,
	components []string,
) {
	t.Helper()

	signer, err := httpsig.NewSigner(
		httpsig.Key{KeyID: KeyID, Algorithm: httpsig.Ed25519, Key: privateKey},
		httpsig.WithComponents(components...),
		httpsig.WithTag(Tag),
	)
	require.NoError(t, err)

	headers, err := signer.Sign(httpsig.MessageFromRequest(req))
	require.NoError(t, err)

	req.Header = headers
}

func VerifyRequest(
	t *testing.T,
	req *http.Request,
	privateKey ed25519.PrivateKey,
	components []string,
) {
	t.Helper()

	verifier, err := httpsig.NewVerifier(
		httpsig.Key{
			KeyID:     KeyID,
			Algorithm: httpsig.Ed25519,
			Key:       privateKey.Public(),
		},
		httpsig.WithRequiredTag(Tag, httpsig.WithRequiredComponents(components...)),
	)
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(httpsig.MessageFromRequest(req)))
}

type Backend struct {
	Target      *url.URL
	ForwardHost bool
}

func (b Backend) URL() *url.URL {
	return b.Target
}

func (b Backend) ForwardHostHeader() bool {
	return b.ForwardHost
}

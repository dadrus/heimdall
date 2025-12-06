package registry_test

import (
	"fmt"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authenticators"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/authorizers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/contextualizers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/errorhandlers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/finalizers"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/validation"
)

func TestRegisterAndCreate(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		registerMechanism func(t *testing.T)
		kind              types.Kind
		typ               string
		name              string
		expErr            bool
	}{
		"mechanism type registered and successfully instantiated": {
			kind: types.KindAuthenticator,
			typ:  "1",
			name: "foo",
			registerMechanism: func(t *testing.T) {
				t.Helper()

				registry.Register(
					types.KindAuthenticator,
					"1",
					registry.FactoryFunc(func(_ app.Context, _ string, _ map[string]any) (types.Mechanism, error) {
						return mocks.NewMechanismMock(t), nil
					}),
				)
			},
		},
		"not registered mechanism cannot be instantiated": {
			kind:              types.KindFinalizer,
			typ:               "2",
			name:              "foo",
			registerMechanism: func(t *testing.T) { t.Helper() },
			expErr:            true,
		},
		"using wrong kind while instantiating a mechanism": {
			kind: types.KindFinalizer,
			typ:  "3",
			name: "foo",
			registerMechanism: func(t *testing.T) {
				t.Helper()

				registry.Register(
					types.KindAuthenticator,
					"3",
					registry.FactoryFunc(func(_ app.Context, _ string, _ map[string]any) (types.Mechanism, error) {
						return mocks.NewMechanismMock(t), nil
					}),
				)
			},
			expErr: true,
		},
		"using wrong type while instantiating a mechanism": {
			kind: types.KindFinalizer,
			typ:  "5",
			name: "foo",
			registerMechanism: func(t *testing.T) {
				t.Helper()

				registry.Register(
					types.KindFinalizer,
					"4",
					registry.FactoryFunc(func(_ app.Context, _ string, _ map[string]any) (types.Mechanism, error) {
						return mocks.NewMechanismMock(t), nil
					}),
				)
			},
			expErr: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			tc.registerMechanism(t)

			// WHEN
			mech, err := registry.Create(nil, tc.kind, tc.typ, tc.name, nil)

			// THEN
			if tc.expErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, mech)
			}
		})
	}
}

func TestAllMechanismsAreRegistered(t *testing.T) {
	t.Parallel()

	validator, err := validation.NewValidator(
		validation.WithTagValidator(config.EnforcementSettings{}),
	)
	require.NoError(t, err)

	ctx := app.NewContextMock(t)
	ctx.EXPECT().Logger().Return(log.Logger)
	ctx.EXPECT().Validator().Maybe().Return(validator)

	for kind, types := range map[types.Kind][]string{
		types.KindAuthenticator: {
			authenticators.AuthenticatorAnonymous,
			authenticators.AuthenticatorBasicAuth,
			authenticators.AuthenticatorGeneric,
			authenticators.AuthenticatorJWT,
			authenticators.AuthenticatorUnauthorized,
		},
		types.KindAuthorizer: {
			authorizers.AuthorizerAllow,
			authorizers.AuthorizerCEL,
			authorizers.AuthorizerDeny,
			authorizers.AuthorizerRemote,
		},
		types.KindContextualizer: {
			contextualizers.ContextualizerGeneric,
			contextualizers.ContextualizerMap,
		},
		types.KindFinalizer: {
			finalizers.FinalizerCookie,
			finalizers.FinalizerHeader,
			finalizers.FinalizerJwt,
			finalizers.FinalizerNoop,
			finalizers.FinalizerOAuth2ClientCredentials,
		},
		types.KindErrorHandler: {
			errorhandlers.ErrorHandlerDefault,
			errorhandlers.ErrorHandlerRedirect,
			errorhandlers.ErrorHandlerWWWAuthenticate,
		},
	} {
		for _, typ := range types {
			t.Run(fmt.Sprintf("%s %s is registered", typ, kind), func(t *testing.T) {
				mech, err := registry.Create(ctx, kind, typ, "some name", nil)
				if err != nil {
					require.NotErrorIs(t, err, registry.ErrUnsupportedMechanismType)
				} else {
					require.NotNil(t, mech)
				}
			})
		}
	}
}

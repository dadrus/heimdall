package repository

import (
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/registry"
	"github.com/dadrus/heimdall/internal/validation"
)

func TestRepositoryNew(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		catalogue *config.MechanismCatalogue
		assert    func(t *testing.T, err error, repo *repository)
	}{
		"no catalogue defined": {
			catalogue: &config.MechanismCatalogue{},
			assert: func(t *testing.T, err error, repo *repository) {
				t.Helper()

				require.NoError(t, err)
				require.Empty(t, repo.authenticators)
				require.Empty(t, repo.authorizers)
				require.Empty(t, repo.contextualizers)
				require.Empty(t, repo.finalizers)
				require.Empty(t, repo.errorHandlers)
			},
		},
		"failed loading catalogue": {
			catalogue: &config.MechanismCatalogue{
				Authorizers: []config.Mechanism{{Name: "foo", Type: "foo"}},
			},
			assert: func(t *testing.T, err error, _ *repository) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, registry.ErrUnsupportedMechanismType)
			},
		},
		"catalogue loaded successfully": {
			catalogue: &config.MechanismCatalogue{
				Authenticators: []config.Mechanism{{Name: "foo", Type: "anonymous"}},
				Authorizers:    []config.Mechanism{{Name: "foo", Type: "deny"}},
				Contextualizers: []config.Mechanism{{
					Name: "foo",
					Type: "generic",
					Config: config.MechanismConfig{
						"endpoint": map[string]any{
							"url": "https://example.com",
						},
					},
				}},
				Finalizers:    []config.Mechanism{{Name: "foo", Type: "noop"}},
				ErrorHandlers: []config.Mechanism{{Name: "foo", Type: "default"}},
			},
			assert: func(t *testing.T, err error, repo *repository) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, repo)

				require.Len(t, repo.authenticators, 1)
				require.Len(t, repo.authorizers, 1)
				require.Len(t, repo.contextualizers, 1)
				require.Len(t, repo.finalizers, 1)
				require.Len(t, repo.errorHandlers, 1)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			validator, err := validation.NewValidator(
				validation.WithTagValidator(config.EnforcementSettings{}),
			)
			require.NoError(t, err)

			ctx := app.NewContextMock(t)
			ctx.EXPECT().Logger().Return(log.Logger)
			ctx.EXPECT().Config().Return(&config.Configuration{Catalogue: tc.catalogue})
			ctx.EXPECT().Validator().Maybe().Return(validator)

			// WHEN
			repo, err := New(ctx)

			// THEN
			var (
				impl *repository
				ok   bool
			)

			if err == nil {
				impl, ok = repo.(*repository)
				require.True(t, ok)
			}

			tc.assert(t, err, impl)
		})
	}
}

func TestRepositoryAuthenticator(t *testing.T) {
	t.Parallel()

	conf := &config.Configuration{
		Catalogue: &config.MechanismCatalogue{
			Authenticators: []config.Mechanism{{Name: "foo", Type: "anonymous"}},
		},
	}

	validator, err := validation.NewValidator(
		validation.WithTagValidator(config.EnforcementSettings{}),
	)
	require.NoError(t, err)

	ctx := app.NewContextMock(t)
	ctx.EXPECT().Logger().Return(log.Logger)
	ctx.EXPECT().Config().Return(conf)
	ctx.EXPECT().Validator().Maybe().Return(validator)

	repo, err := New(ctx)
	require.NoError(t, err)

	// WHEN
	mech, err := repo.Authenticator("foo")

	// THEN
	require.NoError(t, err)
	assert.NotNil(t, mech)
	assert.Equal(t, "foo", mech.Name())

	// WHEN
	_, err = repo.Authenticator("bar")

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMechanismNotFound)
}

func TestRepositoryAuthorizer(t *testing.T) {
	t.Parallel()

	conf := &config.Configuration{
		Catalogue: &config.MechanismCatalogue{
			Authorizers: []config.Mechanism{{Name: "foo", Type: "deny"}},
		},
	}

	validator, err := validation.NewValidator(
		validation.WithTagValidator(config.EnforcementSettings{}),
	)
	require.NoError(t, err)

	ctx := app.NewContextMock(t)
	ctx.EXPECT().Logger().Return(log.Logger)
	ctx.EXPECT().Config().Return(conf)
	ctx.EXPECT().Validator().Maybe().Return(validator)

	repo, err := New(ctx)
	require.NoError(t, err)

	// WHEN
	mech, err := repo.Authorizer("foo")

	// THEN
	require.NoError(t, err)
	assert.NotNil(t, mech)
	assert.Equal(t, "foo", mech.Name())

	// WHEN
	_, err = repo.Authorizer("bar")

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMechanismNotFound)
}

func TestRepositoryContextualizer(t *testing.T) {
	t.Parallel()

	conf := &config.Configuration{
		Catalogue: &config.MechanismCatalogue{
			Contextualizers: []config.Mechanism{
				{
					Name: "foo",
					Type: "generic",
					Config: config.MechanismConfig{
						"endpoint": map[string]any{
							"url": "https://example.com",
						},
					},
				},
			},
		},
	}

	validator, err := validation.NewValidator(
		validation.WithTagValidator(config.EnforcementSettings{}),
	)
	require.NoError(t, err)

	ctx := app.NewContextMock(t)
	ctx.EXPECT().Logger().Return(log.Logger)
	ctx.EXPECT().Config().Return(conf)
	ctx.EXPECT().Validator().Maybe().Return(validator)

	repo, err := New(ctx)
	require.NoError(t, err)

	// WHEN
	mech, err := repo.Contextualizer("foo")

	// THEN
	require.NoError(t, err)
	assert.NotNil(t, mech)
	assert.Equal(t, "foo", mech.Name())

	// WHEN
	_, err = repo.Contextualizer("bar")

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMechanismNotFound)
}

func TestRepositoryFinalizer(t *testing.T) {
	t.Parallel()

	conf := &config.Configuration{
		Catalogue: &config.MechanismCatalogue{
			Finalizers: []config.Mechanism{{Name: "foo", Type: "noop"}},
		},
	}

	validator, err := validation.NewValidator(
		validation.WithTagValidator(config.EnforcementSettings{}),
	)
	require.NoError(t, err)

	ctx := app.NewContextMock(t)
	ctx.EXPECT().Logger().Return(log.Logger)
	ctx.EXPECT().Config().Return(conf)
	ctx.EXPECT().Validator().Maybe().Return(validator)

	repo, err := New(ctx)
	require.NoError(t, err)

	// WHEN
	mech, err := repo.Finalizer("foo")

	// THEN
	require.NoError(t, err)
	assert.NotNil(t, mech)
	assert.Equal(t, "foo", mech.Name())

	// WHEN
	_, err = repo.Finalizer("bar")

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMechanismNotFound)
}

func TestRepositoryErrorHandler(t *testing.T) {
	t.Parallel()

	conf := &config.Configuration{
		Catalogue: &config.MechanismCatalogue{
			ErrorHandlers: []config.Mechanism{{Name: "foo", Type: "default"}},
		},
	}

	validator, err := validation.NewValidator(
		validation.WithTagValidator(config.EnforcementSettings{}),
	)
	require.NoError(t, err)

	ctx := app.NewContextMock(t)
	ctx.EXPECT().Logger().Return(log.Logger)
	ctx.EXPECT().Config().Return(conf)
	ctx.EXPECT().Validator().Maybe().Return(validator)

	repo, err := New(ctx)
	require.NoError(t, err)

	// WHEN
	mech, err := repo.ErrorHandler("foo")

	// THEN
	require.NoError(t, err)
	assert.NotNil(t, mech)
	assert.Equal(t, "foo", mech.Name())

	// WHEN
	_, err = repo.ErrorHandler("bar")

	// THEN
	require.Error(t, err)
	require.ErrorIs(t, err, ErrMechanismNotFound)
}

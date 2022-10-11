package filesystem

import (
	"os"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/x"
)

type mockLifecycle struct{ mock.Mock }

func (m *mockLifecycle) Append(hook fx.Hook) { m.Called(hook) }

func TestRegisterProvider(t *testing.T) {
	t.Parallel()

	tmpFile, err := os.CreateTemp(os.TempDir(), "test-rule-")
	require.NoError(t, err)

	defer os.Remove(tmpFile.Name())

	for _, tc := range []struct {
		uc         string
		conf       config.Configuration
		setupMocks func(t *testing.T, mockLC *mockLifecycle)
		assert     func(t *testing.T, err error)
	}{
		{
			uc: "without it being configured",
			assert: func(t *testing.T, err error) {
				t.Helper()

				assert.NoError(t, err)
			},
		},
		{
			uc: "without provided rules file/directory",
			conf: config.Configuration{
				Rules: config.RulesConfig{
					Providers: config.RuleProviders{
						FileSystem: &config.FileBasedRuleProviderConfig{},
					},
				},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.ErrorIs(t, err, heimdall.ErrConfiguration)
			},
		},
		{
			uc: "with not existing referenced file",
			conf: config.Configuration{
				Rules: config.RulesConfig{
					Providers: config.RuleProviders{
						FileSystem: &config.FileBasedRuleProviderConfig{Src: "foo.bar"},
					},
				},
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				assert.Contains(t, err.Error(), "no such file")
			},
		},
		{
			uc: "with existing rules file",
			conf: config.Configuration{
				Rules: config.RulesConfig{
					Providers: config.RuleProviders{
						FileSystem: &config.FileBasedRuleProviderConfig{Src: tmpFile.Name()},
					},
				},
			},
			setupMocks: func(t *testing.T, mockLC *mockLifecycle) {
				t.Helper()

				mockLC.On("Append", mock.AnythingOfType("fx.Hook"))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "with existing rules file and enabled watcher",
			conf: config.Configuration{
				Rules: config.RulesConfig{
					Providers: config.RuleProviders{
						FileSystem: &config.FileBasedRuleProviderConfig{Src: tmpFile.Name(), Watch: true},
					},
				},
			},
			setupMocks: func(t *testing.T, mockLC *mockLifecycle) {
				t.Helper()

				mockLC.On("Append", mock.AnythingOfType("fx.Hook"))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run("case="+tc.uc, func(t *testing.T) {
			// GIVEN
			mlc := &mockLifecycle{}
			queue := make(event.RuleSetChangedEventQueue, 10)
			setupMocks := x.IfThenElse(tc.setupMocks != nil,
				tc.setupMocks,
				func(t *testing.T, mockLC *mockLifecycle) { t.Helper() })

			setupMocks(t, mlc)

			// WHEN
			err := registerProvider(registrationArguments{Lifecycle: mlc, Config: tc.conf, Queue: queue}, log.Logger)

			// THEN
			tc.assert(t, err)

			mlc.AssertExpectations(t)
		})
	}
}

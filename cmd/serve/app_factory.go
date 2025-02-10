package serve

import (
	"bytes"
	"slices"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"

	"github.com/dadrus/heimdall/cmd/flags"
	"github.com/dadrus/heimdall/internal"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/logging"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/version"
)

func createApp(cmd *cobra.Command, mainModule fx.Option) (*fx.App, error) {
	configPath, _ := cmd.Flags().GetString(flags.Config)
	envPrefix, _ := cmd.Flags().GetString(flags.EnvironmentConfigPrefix)
	cli := bytes.NewBufferString(cmd.CommandPath())
	securityEnforcementDisabled := false

	cmd.Flags().Visit(func(flag *pflag.Flag) {
		cli.WriteString(" --")
		cli.WriteString(flag.Name)
		cli.WriteString(" ")
		cli.WriteString(flag.Value.String())

		if slices.Contains(flags.InsecureFlags, flag.Name) {
			securityEnforcementDisabled = true
		}
	})

	es := flags.EnforcementSettings(cmd)

	validator, err := validation.NewValidator(
		validation.WithTagValidator(es),
		validation.WithErrorTranslator(es),
	)
	if err != nil {
		return nil, err
	}

	cfg, err := config.NewConfiguration(
		config.EnvVarPrefix(envPrefix),
		config.ConfigurationPath(configPath),
		validator,
	)
	if err != nil {
		return nil, err
	}

	logger := logging.NewLogger(cfg.Log)
	logger.Info().
		Str("_version", version.Version).
		Str("_cli", cli.String()).
		Msg("Starting heimdall")

	if securityEnforcementDisabled {
		logger.Warn().Msg("Enforcement of secure settings disabled")
	}

	app := fx.New(
		fx.Supply(
			cfg,
			logger,
			config.SecureDefaultRule(es.EnforceSecureDefaultRule),
			fx.Annotate(validator, fx.As(new(validation.Validator))),
		),
		fx.WithLogger(func(logger zerolog.Logger) fxevent.Logger {
			return &eventLogger{l: logger}
		}),
		internal.Module,
		mainModule,
	)

	return app, app.Err()
}

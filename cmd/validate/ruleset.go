package validate

import (
	"context"
	"os"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/rules"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/rules/mechanisms"
	"github.com/dadrus/heimdall/internal/rules/provider/filesystem"
)

// NewValidateRulesCommand represents the "validate rules" command.
func NewValidateRulesCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "rules [path to ruleset]",
		Short:   "Validates heimdall's ruleset",
		Args:    cobra.ExactArgs(1),
		Example: "heimdall validate rules -c myconfig.yaml myruleset.yaml",
		Run: func(cmd *cobra.Command, args []string) {
			if err := validateRuleSet(cmd, args); err != nil {
				cmd.PrintErrf("%v\n", err)

				os.Exit(1)
			}

			cmd.Println("Rule set is valid")
		},
	}
}

func validateRuleSet(cmd *cobra.Command, args []string) error {
	const queueSize = 50

	configPath, _ := cmd.Flags().GetString("config")
	if len(configPath) == 0 {
		return ErrNoConfigFile
	}

	envPrefix, _ := cmd.Flags().GetString("env-config-prefix")

	conf, err := config.NewConfiguration(
		config.EnvVarPrefix(envPrefix),
		config.ConfigurationPath(configPath),
	)
	if err != nil {
		return err
	}

	conf.Rules.Providers.FileSystem = map[string]any{"src": args[0]}

	logger := zerolog.Nop()

	mFactory, err := mechanisms.NewFactory(conf, logger)
	if err != nil {
		return err
	}

	rFactory, err := rules.NewRuleFactory(mFactory, conf, logger)
	if err != nil {
		return err
	}

	queue := make(event.RuleSetChangedEventQueue, queueSize)

	defer close(queue)

	provider, err := filesystem.NewProvider(conf, rules.NewRuleSetProcessor(queue, rFactory, logger), logger)
	if err != nil {
		return err
	}

	return provider.Start(context.Background())
}

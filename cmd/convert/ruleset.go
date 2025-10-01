package convert

import (
	"os"

	"github.com/dadrus/heimdall/internal/conversion"
	"github.com/spf13/cobra"
)

const (
	convertRuleSetFlagDesiredVersion = "desired-version"
	convertRuleSetFlagInputFile      = "in"
	convertRuleSetFlagOutputFile     = "out"
)

// NewConvertRulesCommand represents the "convert rules" command.
func NewConvertRulesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules --desired-version <desired version> --in <path/to/ruleset> --out <path/to/converted/ruleset>",
		Short: "Converts heimdall's ruleset",
		Args:  cobra.ExactArgs(1),
		Example: `heimdall convert rules --desired_version v1beta1 \
   --in /path/to/ruleset.yaml \
   --out /path/to/converted/ruleset.yaml`,
		SilenceUsage: true,
		RunE:         convertRuleSet,
	}

	cmd.PersistentFlags().String(convertRuleSetFlagDesiredVersion, "", "Target version of the resulting RuleSet")
	cmd.PersistentFlags().String(convertRuleSetFlagInputFile, "", "RuleSet file to convert")
	cmd.PersistentFlags().String(convertRuleSetFlagOutputFile, "", "File to write the conversion result to")

	return cmd
}

func convertRuleSet(cmd *cobra.Command, _ []string) error {
	inputFile, err := cmd.Flags().GetString(convertRuleSetFlagInputFile)
	if err != nil {
		return err
	}

	outputFile, err := cmd.Flags().GetString(convertRuleSetFlagOutputFile)
	if err != nil {
		return err
	}

	targetVersion, err := cmd.Flags().GetString(convertRuleSetFlagDesiredVersion)
	if err != nil {
		return err
	}

	contents, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	conv := conversion.NewRuleSetConverter(targetVersion)

	result, err := conv.ConvertRuleSet(contents)
	if err != nil {
		return err
	}

	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}

	_, err = file.Write(result)
	if err != nil {
		return err
	}

	return nil
}

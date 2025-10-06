package convert

import (
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dadrus/heimdall/internal/conversion"
)

const (
	convertRuleSetFlagDesiredVersion = "desired-version"
	convertRuleSetFlagOutputFile     = "out"
)

// NewConvertRulesCommand represents the "convert rules" command.
func NewConvertRulesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ruleset [options] /path/to/ruleset.yaml",
		Short: "Converts heimdall's RuleSet",
		Example: `heimdall convert ruleset --desired-version v1beta1 \
   --out /path/to/converted/ruleset.yaml \
   /path/to/ruleset.yaml`,
		Args: cobra.ExactArgs(1),
		RunE: convertRuleSet,
	}

	cmd.Flags().String(convertRuleSetFlagDesiredVersion, "",
		"Target version of the resulting RuleSet (required)")
	_ = cmd.MarkFlagRequired(convertRuleSetFlagDesiredVersion)
	cmd.Flags().String(convertRuleSetFlagOutputFile, "",
		"File to write the conversion result to. If not used, the converted"+
			" ruleset is written to the standard output")

	return cmd
}

func convertRuleSet(cmd *cobra.Command, args []string) error {
	inputFile := args[0]
	outputFile, _ := cmd.Flags().GetString(convertRuleSetFlagOutputFile)
	targetVersion, _ := cmd.Flags().GetString(convertRuleSetFlagDesiredVersion)
	conv := conversion.NewRuleSetConverter(targetVersion)

	contents, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	contentType := "unknown"
	if strings.HasSuffix(inputFile, ".yaml") || strings.HasSuffix(inputFile, ".yml") {
		contentType = "application/yaml"
	} else if strings.HasSuffix(inputFile, ".json") {
		contentType = "application/json"
	}

	result, err := conv.ConvertRuleSet(contents, contentType)
	if err != nil {
		return err
	}

	var out io.Writer

	if len(outputFile) == 0 {
		out = cmd.OutOrStdout()
	} else {
		out, err = os.Create(outputFile)
		if err != nil {
			return err
		}
	}

	_, err = out.Write(result)

	return err
}

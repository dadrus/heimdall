package convert

import (
	"bytes"
	"errors"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/encoding"
	"github.com/dadrus/heimdall/internal/rules/converter"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x"
)

const (
	convertRuleSetFlagDesiredVersion = "desired-version"
	convertRuleSetFlagOutputFile     = "out"
)

var ErrEmptyRuleset = errors.New("ruleset must not be empty")

// NewConvertRulesCommand represents the "convert rules" command.
func NewConvertRulesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ruleset [flags] [/path/to/ruleset.yaml]",
		Short: "Converts rulesets between 1alpha4 and 1beta1 versions",
		Example: `# Convert a ruleset by providing all arguments
$ heimdall convert ruleset --desired-version 1beta1 --out converted_ruleset.yaml ruleset.yaml

# Convert a ruleset by providing it over stdin and printing the results to stdout
$ cat ruleset.yaml | heimdall convert ruleset --desired-version 1beta1 > converted.yaml`,
		Args:                  cobra.MaximumNArgs(1),
		DisableFlagsInUseLine: true,
		RunE:                  convertRuleSet,
	}

	cmd.Flags().StringP(convertRuleSetFlagDesiredVersion, "v", "",
		"Target version (1alpha4 or 1beta1) of the resulting RuleSet (required)")
	_ = cmd.MarkFlagRequired(convertRuleSetFlagDesiredVersion)
	cmd.Flags().StringP(convertRuleSetFlagOutputFile, "o", "",
		"File to write the conversion result to. If not used, the converted"+
			" ruleset is written to the standard output")

	return cmd
}

func convertRuleSet(cmd *cobra.Command, args []string) error {
	es := config.EnforcementSettings{}

	validator, err := validation.NewValidator(
		validation.WithTagValidator(es),
		validation.WithErrorTranslator(es),
	)
	if err != nil {
		return err
	}

	inputFileName := x.IfThenElseExec(len(args) != 0,
		func() string { return args[0] },
		func() string { return "" },
	)
	outputFileName, _ := cmd.Flags().GetString(convertRuleSetFlagOutputFile)
	targetVersion, _ := cmd.Flags().GetString(convertRuleSetFlagDesiredVersion)
	conv := converter.New(targetVersion, encoding.ValidatorFunc(validator.ValidateStruct))

	var in io.Reader
	if len(inputFileName) == 0 {
		in = cmd.InOrStdin()
	} else {
		file, err := os.Open(inputFileName)
		if err != nil {
			return err
		}

		defer file.Close()

		in = file
	}

	contents, err := io.ReadAll(in)
	if err != nil {
		return err
	}

	contents = bytes.TrimSpace(contents)
	if len(contents) == 0 {
		return ErrEmptyRuleset
	}

	contentType := "application/yaml"
	if len(contents) != 0 && contents[0] == '{' {
		contentType = "application/json"
	}

	result, err := conv.Convert(contents, contentType)
	if err != nil {
		return err
	}

	var out io.Writer

	if len(outputFileName) == 0 {
		out = cmd.OutOrStdout()
	} else {
		out, err = os.Create(outputFileName)
		if err != nil {
			return err
		}
	}

	_, err = out.Write(result)

	return err
}

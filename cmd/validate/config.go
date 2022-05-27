package validate

import (
	"os"

	"github.com/goccy/go-json"
	"github.com/spf13/cobra"
	"github.com/xeipuuv/gojsonschema"
	"gopkg.in/yaml.v3"

	"github.com/dadrus/heimdall/schema"
)

// NewValidateConfig represents the "validate config" command.
func NewValidateConfig() *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Validates heimdall's configuration",
		Run: func(cmd *cobra.Command, args []string) {
			configPath, _ := cmd.Flags().GetString("config")

			file, err := os.Stat(configPath)
			if err != nil {
				cmd.PrintErrf("Could not open %s: %v\n", configPath, err)

				os.Exit(-1)
			}

			contents, err := os.ReadFile(file.Name())
			if err != nil {
				cmd.PrintErrf("Could not read %s: %v\n", configPath, err)

				os.Exit(-1)
			}

			var conf map[string]any
			err = yaml.Unmarshal(contents, &conf)
			if err != nil {
				cmd.PrintErrf("Failed to parse %s: %v\n", configPath, err)

				os.Exit(-1)
			}

			jsonConf, err := json.Marshal(conf)
			if err != nil {
				cmd.PrintErrf("Failed to convert contents of %s to JSON: %v\n", configPath, err)

				os.Exit(-1)
			}

			schemaLoader := gojsonschema.NewBytesLoader(schema.ConfigSchema)
			documentLoader := gojsonschema.NewBytesLoader(jsonConf)

			result, err := gojsonschema.Validate(schemaLoader, documentLoader)
			if err != nil {
				cmd.PrintErrf("Failed to validate schema due to an internal error: %v\n", err)

				os.Exit(-1)
			}

			if !result.Valid() {
				cmd.Printf("Configuration is not valid. see errors :\n")
				for _, desc := range result.Errors() {
					cmd.Printf("- %s\n", desc)
				}

				os.Exit(-1)
			}

			cmd.Printf("Configuration is valid\n")
		},
	}
}

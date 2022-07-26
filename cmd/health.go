package cmd

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/goccy/go-json"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/dadrus/heimdall/internal/handler/management"
)

// nolint: gochecknoglobals
var healthCmd = &cobra.Command{
	Use:     "health",
	Short:   "Checks the health status of a Heimdall deployment",
	Example: "heimdall health -e https://heimdall.local",
	Run: func(cmd *cobra.Command, args []string) {
		endpointURL, _ := cmd.Flags().GetString("endpoint")
		outputFormat, _ := cmd.Flags().GetString("output")

		resp, err := http.DefaultClient.Get(fmt.Sprintf("%s%s", endpointURL, management.EndpointHealth))
		if err != nil {
			cmd.PrintErrf("Failed to send request: %v", err)
			os.Exit(-1)
		}

		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			cmd.PrintErrf("Unexpected HTTP status code : %s", resp.Status)
			os.Exit(-1)
		}

		rawResp, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			cmd.PrintErrf("Failed to read response: %v", err)
			os.Exit(-1)
		}

		var structuredResponse map[string]any
		if err := json.Unmarshal(rawResp, &structuredResponse); err != nil {
			cmd.PrintErrf("Failed to unmarshal response: %v", err)
			os.Exit(-1)
		}

		switch outputFormat {
		case "json":
			cmd.Println(string(rawResp))
		case "yaml":
			rawYaml, err := yaml.Marshal(structuredResponse)
			if err != nil {
				cmd.PrintErrf("Failed to convert response to yaml: %v", err)
				os.Exit(-1)
			}
			cmd.Println(string(rawYaml))
		default:
			cmd.Println(structuredResponse["status"])
		}
	},
}

// nolint: gochecknoinits
func init() {
	RootCmd.AddCommand(healthCmd)

	healthCmd.PersistentFlags().StringP("endpoint", "e", "", `The base URL of Heimdall's deployment. 
Note: The endpoint URL should point to a single Heimdall deployment. 
If the endpoint URL points to a Load Balancer, these commands will effective test the Load Balancer.`)
	healthCmd.PersistentFlags().StringP("output", "o", "text", `The format for the result output.
Can be "json", "text", or "yaml".`)
}

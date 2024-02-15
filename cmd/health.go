// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/goccy/go-json"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/dadrus/heimdall/internal/handler/management"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

// nolint: gochecknoglobals
var healthCmd = &cobra.Command{
	Use:     "health",
	Short:   "Checks the health status of a Heimdall deployment",
	Example: "heimdall health -e https://heimdall.local",
	Run: func(cmd *cobra.Command, _ []string) {
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

		rawResp, err := io.ReadAll(resp.Body)
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
			cmd.Println(stringx.ToString(rawResp))
		case "yaml":
			rawYaml, err := yaml.Marshal(structuredResponse)
			if err != nil {
				cmd.PrintErrf("Failed to convert response to yaml: %v", err)
				os.Exit(-1)
			}
			cmd.Println(stringx.ToString(rawYaml))
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

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
)

const (
	healthFlagEndpoint = "endpoint"
	healthFlagOutput   = "output"
)

// nolint: gochecknoinits
func init() {
	RootCmd.AddCommand(newHealthCmd())
}

func newHealthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "health",
		Short:   "Checks the health status of a Heimdall deployment",
		Example: "heimdall health -e https://heimdall.local",
		Run: func(cmd *cobra.Command, _ []string) {
			status, err := healthStatus(cmd)
			if err != nil {
				cmd.PrintErrf("%v", err)

				os.Exit(1)
			}

			cmd.Println(status)
		},
	}

	cmd.PersistentFlags().StringP(healthFlagEndpoint, "e", "", `The base URL of Heimdall's deployment. 
Note: The endpoint URL should point to a single Heimdall deployment. 
If the endpoint URL points to a Load Balancer, these commands will effective test the Load Balancer.`)
	cmd.PersistentFlags().StringP(healthFlagOutput, "o", "text", `The format for the result output.
Can be "json", "text", or "yaml".`)

	return cmd
}

func healthStatus(cmd *cobra.Command) (string, error) {
	endpointURL, _ := cmd.Flags().GetString(healthFlagEndpoint)
	outputFormat, _ := cmd.Flags().GetString(healthFlagOutput)

	resp, err := http.DefaultClient.Get(endpointURL + management.EndpointHealth)
	if err != nil {
		return "", fmt.Errorf("Failed to send request: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Unexpected HTTP status code : %s", resp.Status)
	}

	rawResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("Failed to read response: %v", err)
	}

	var structuredResponse map[string]any
	if err = json.Unmarshal(rawResp, &structuredResponse); err != nil {
		return "", fmt.Errorf("Failed to unmarshal response: %v", err)
	}

	switch outputFormat {
	case "json":
		return string(rawResp), nil
	case "yaml":
		rawYaml, err := yaml.Marshal(structuredResponse)
		if err != nil {
			return "", fmt.Errorf("Failed to convert response to yaml: %v", err)
		}

		return string(rawYaml), nil
	default:
		return fmt.Sprintf("%v", structuredResponse["status"]), nil
	}
}

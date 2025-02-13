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
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/goccy/go-json"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/dadrus/heimdall/internal/handler/management"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
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

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		endpointURL+management.EndpointHealth,
		nil,
	)
	if err != nil {
		return "", errorchain.NewWithMessagef(heimdall.ErrInternal, "Failed to send request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", errorchain.NewWithMessagef(heimdall.ErrCommunication, "Failed to send request: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errorchain.NewWithMessagef(heimdall.ErrCommunication, "Unexpected HTTP status code : %s", resp.Status)
	}

	rawResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errorchain.NewWithMessagef(heimdall.ErrCommunication, "Failed to read response: %v", err)
	}

	var structuredResponse map[string]any
	if err = json.Unmarshal(rawResp, &structuredResponse); err != nil {
		return "", errorchain.NewWithMessagef(heimdall.ErrCommunication, "Failed to unmarshal response: %v", err)
	}

	switch outputFormat {
	case "json":
		return string(rawResp), nil
	case "yaml":
		rawYaml, _ := yaml.Marshal(structuredResponse)

		return string(rawYaml), nil
	default:
		return fmt.Sprintf("%v", structuredResponse["status"]), nil
	}
}

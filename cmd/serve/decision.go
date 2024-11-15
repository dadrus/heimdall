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

package serve

import (
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/cmd/flags"
	"github.com/dadrus/heimdall/internal"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/decision"
	envoy_extauth "github.com/dadrus/heimdall/internal/handler/envoyextauth/grpcv3"
)

const serveDecisionFlagEnvoyGRPC = "envoy-grpc"

// NewDecisionCommand represents the "serve decision" command.
func NewDecisionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "decision",
		Short:   "Starts heimdall in Decision operation mode",
		Example: "heimdall serve decision",
		Run: func(cmd *cobra.Command, _ []string) {
			app, err := createDecisionApp(cmd)
			if err != nil {
				cmd.PrintErrf("Failed to initialize decision service: %v", err)

				os.Exit(1)
			}

			app.Run()
		},
	}

	cmd.PersistentFlags().Bool(serveDecisionFlagEnvoyGRPC, false,
		"If specified, decision mode is started for integration with envoy extauth gRPC service")

	return cmd
}

func createDecisionApp(cmd *cobra.Command) (*fx.App, error) {
	configPath, _ := cmd.Flags().GetString(flags.Config)
	envPrefix, _ := cmd.Flags().GetString(flags.EnvironmentConfigPrefix)
	useEnvoyExtAuth, _ := cmd.Flags().GetBool(serveDecisionFlagEnvoyGRPC)

	opts := []fx.Option{
		fx.NopLogger,
		fx.Supply(
			config.ConfigurationPath(configPath),
			config.EnvVarPrefix(envPrefix),
			flags.EnforcementSettings(cmd),
			config.DecisionMode,
		),
		internal.Module,
	}

	if useEnvoyExtAuth {
		opts = append(opts, envoy_extauth.Module)
	} else {
		opts = append(opts, decision.Module)
	}

	app := fx.New(opts...)

	return app, app.Err()
}

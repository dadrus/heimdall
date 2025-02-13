// Copyright 2022-2025 Dimitrij Drus <dadrus@gmx.de>
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
	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/decision"
	envoy_extauth "github.com/dadrus/heimdall/internal/handler/envoyextauth/grpcv3"
	"github.com/dadrus/heimdall/internal/x"
)

const serveDecisionFlagEnvoyGRPC = "envoy-grpc"

// NewDecisionCommand represents the "serve decision" command.
func NewDecisionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "decision",
		Short:   "Starts heimdall in Decision operation mode",
		Example: "heimdall serve decision",
		RunE: func(cmd *cobra.Command, _ []string) error {
			useEnvoyExtAuth, _ := cmd.Flags().GetBool(serveDecisionFlagEnvoyGRPC)

			app, err := createApp(
				cmd,
				fx.Options(
					x.IfThenElse(useEnvoyExtAuth, envoy_extauth.Module, decision.Module),
					fx.Supply(config.DecisionMode),
				),
			)
			if err != nil {
				return err
			}

			app.Run()

			return nil
		},
	}

	cmd.PersistentFlags().Bool(serveDecisionFlagEnvoyGRPC, false,
		"If specified, decision mode is started for integration with envoy extauth gRPC service")

	return cmd
}

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

package decision

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/handler/requestcontext"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
)

type Handler struct {
	f requestcontext.ContextFactory
	e rule.Executor
}

type handlerArgs struct {
	fx.In

	App    *fiber.App `name:"decision"`
	Exec   rule.Executor
	Config *config.Configuration
	Signer heimdall.JWTSigner
	Logger zerolog.Logger
}

func newHandler(args handlerArgs) (*Handler, error) {
	acceptedCode := args.Config.Serve.Decision.Respond.With.Accepted.Code

	handler := &Handler{
		f: requestcontext.NewDecisionContextFactory(args.Signer,
			x.IfThenElse(acceptedCode != 0, acceptedCode, fiber.StatusOK)),
		e: args.Exec,
	}

	handler.registerRoutes(args.App.Group("/"), args.Logger)

	return handler, nil
}

func (h *Handler) registerRoutes(router fiber.Router, logger zerolog.Logger) {
	logger.Debug().Msg("Registering decision service routes")

	router.All("/*", h.decisions)
}

func (h *Handler) decisions(c *fiber.Ctx) error {
	rc := h.f.Create(c)

	mut, err := h.e.Execute(rc)
	if err != nil {
		return err
	}

	return rc.Finalize(mut)
}

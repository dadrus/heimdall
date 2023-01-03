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

package management

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/etag"
	"github.com/rs/zerolog"
	"go.uber.org/fx"

	"github.com/dadrus/heimdall/internal/heimdall"
)

type Handler struct{}

type handlerArgs struct {
	fx.In

	App    *fiber.App `name:"management"`
	Signer heimdall.JWTSigner
	Logger zerolog.Logger
}

func newHandler(args handlerArgs) (*Handler, error) {
	handler := &Handler{}

	handler.registerRoutes(args.App.Group("/"), args.Logger, args.Signer)

	return handler, nil
}

func (h *Handler) registerRoutes(router fiber.Router, logger zerolog.Logger, signer heimdall.JWTSigner) {
	logger.Debug().Msg("Registering Management service routes")

	router.Get(EndpointHealth, health)
	router.Get(EndpointJWKS, etag.New(), jwks(signer))
}

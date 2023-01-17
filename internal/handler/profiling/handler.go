// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package profiling

import (
	"net/http"
	"net/http/pprof"

	"github.com/gofiber/adaptor/v2"
	"github.com/gofiber/fiber/v2"
)

func registerRoutes(router fiber.Router) {
	router.Get("/debug/pprof/", adaptor.HTTPHandler(http.HandlerFunc(pprof.Index)))
	router.Get("/debug/pprof/cmdline", adaptor.HTTPHandler(http.HandlerFunc(pprof.Cmdline)))
	router.Get("/debug/pprof/profile", adaptor.HTTPHandler(http.HandlerFunc(pprof.Profile)))
	router.Get("/debug/pprof/symbol", adaptor.HTTPHandler(http.HandlerFunc(pprof.Symbol)))
	router.Get("/debug/pprof/trace", adaptor.HTTPHandler(http.HandlerFunc(pprof.Trace)))
}

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

package service

import (
	"net/http"

	"github.com/dadrus/heimdall/internal/handler/middleware/http/errorhandler"
)

type requestCoordinator interface {
	Handle(req *http.Request, rw http.ResponseWriter) (struct{}, error)
}

type handler struct {
	c  requestCoordinator
	eh errorhandler.ErrorHandler
}

func NewHandler(coordinator requestCoordinator, eh errorhandler.ErrorHandler) http.Handler {
	return &handler{
		c:  coordinator,
		eh: eh,
	}
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if _, err := h.c.Handle(req, rw); err != nil {
		h.eh.HandleError(rw, req, err)
	}
}

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

package recovery

import (
	"fmt"
	"net/http"
	"runtime/debug"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/handler/middleware/http/errorhandler"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
)

func New(eh errorhandler.ErrorHandler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			defer func() { //nolint:contextcheck
				if rec := recover(); rec != nil {
					zerolog.Ctx(req.Context()).Error().Msg(fmt.Sprintf("%v\n%s", rec, stringx.ToString(debug.Stack())))

					err, ok := rec.(error)
					if ok {
						err = errorchain.NewWithMessage(heimdall.ErrInternal, "runtime error occurred").
							CausedBy(err)
					} else {
						err = errorchain.NewWithMessage(heimdall.ErrInternal, "runtime error occurred").
							CausedBy(fmt.Errorf("%v", rec)) //nolint: err113
					}

					eh.HandleError(rw, req, err)
				}
			}()

			next.ServeHTTP(rw, req)
		})
	}
}

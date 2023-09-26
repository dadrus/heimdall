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
	"net/http"

	"github.com/goccy/go-json"
)

func health() http.Handler {
	type status struct {
		Status string `json:"status"`
	}

	return http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		res, err := json.Marshal(status{Status: "ok"})
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)

			return
		}

		rw.Header().Set("Content-Type", "application/json")
		rw.Write(res)
	})
}

// Copyright 2026 Dimitrij Drus
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package pem

import (
	"os"

	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func readFile(path string) ([]byte, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, errorchain.NewWithMessagef(provider.ErrConfiguration,
			"failed to read %s", path).CausedBy(err)
	}

	return contents, nil
}

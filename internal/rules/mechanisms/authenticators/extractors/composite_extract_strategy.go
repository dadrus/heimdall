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

package extractors

import (
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type CompositeExtractStrategy []AuthDataExtractStrategy

func (ce CompositeExtractStrategy) GetAuthData(ctx heimdall.RequestContext) (string, error) {
	// preallocation not possible
	var errors []error //nolint:prealloc

	for _, e := range ce {
		val, err := e.GetAuthData(ctx)
		if err == nil {
			return val, nil
		}

		errors = append(errors, err)
	}

	err := errorchain.New(errors[0])
	for i := 1; i < len(errors); i++ {
		err = err.CausedBy(errors[i])
	}

	return "", err
}

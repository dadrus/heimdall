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

package matcher

import "errors"

type ErrorDescriptor struct {
	Errors    []error
	HandlerID string
}

func (ed ErrorDescriptor) Matches(err error) bool {
	if !ed.matchesError(err) {
		return false
	}

	if !ed.matchesHandlerID(err) {
		return false
	}

	return true
}

func (ed ErrorDescriptor) matchesHandlerID(err error) bool {
	if len(ed.HandlerID) == 0 {
		return true
	}

	var handlerIdentifier interface{ ID() string }
	ok := errors.As(err, &handlerIdentifier)

	return ok && ed.HandlerID == handlerIdentifier.ID()
}

func (ed ErrorDescriptor) matchesError(err error) bool {
	for _, v := range ed.Errors {
		if errors.Is(err, v) {
			return true
		}
	}

	return false
}

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

package config

type Matcher struct {
	Path                string              `json:"path"                 yaml:"path"                 validate:"required"`              //nolint:lll,tagalign
	BacktrackingEnabled *bool               `json:"backtracking_enabled" yaml:"backtracking_enabled" validate:"excluded_without=With"` //nolint:lll,tagalign
	With                *MatcherConstraints `json:"with"                 yaml:"with"                 validate:"omitnil,required"`      //nolint:lll,tagalign
}

func (m *Matcher) DeepCopyInto(out *Matcher) {
	*out = *m

	if m.With != nil {
		in, out := m.With, out.With

		in.DeepCopyInto(out)
	}
}

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

import (
	"slices"
)

type MatcherConstraints struct {
	Scheme    string `json:"scheme"     yaml:"scheme"     validate:"omitempty,oneof=http https"` //nolint:tagalign
	HostGlob  string `json:"host_glob"  yaml:"host_glob"  validate:"excluded_with=HostRegex"`    //nolint:tagalign
	HostRegex string `json:"host_regex" yaml:"host_regex" validate:"excluded_with=HostGlob"`     //nolint:tagalign
	PathGlob  string `json:"path_glob"  yaml:"path_glob"  validate:"excluded_with=PathRegex"`    //nolint:tagalign
	PathRegex string `json:"path_regex" yaml:"path_regex" validate:"excluded_with=PathGlob"`     //nolint:tagalign
}

type Matcher struct {
	Path    string             `json:"path"    yaml:"path"    validate:"required"`           //nolint:tagalign
	Methods []string           `json:"methods" yaml:"methods" validate:"gt=0,dive,required"` //nolint:tagalign
	With    MatcherConstraints `json:"with"    yaml:"with"`
}

func (m *Matcher) DeepCopyInto(out *Matcher) {
	*out = *m
	out.Methods = slices.Clone(m.Methods)
}

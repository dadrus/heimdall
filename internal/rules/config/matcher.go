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

import "slices"

type Matcher struct {
	Routes              []Route       `json:"routes"               yaml:"routes"               validate:"required,dive"`              //nolint:lll,tagalign
	BacktrackingEnabled *bool         `json:"backtracking_enabled" yaml:"backtracking_enabled"`                                       //nolint:lll,tagalign
	Scheme              string        `json:"scheme"               yaml:"scheme"               validate:"omitempty,oneof=http https"` //nolint:lll,tagalign
	Methods             []string      `json:"methods"              yaml:"methods"              validate:"omitempty,dive,required"`    //nolint:lll,tagalign
	Hosts               []HostMatcher `json:"hosts"                yaml:"hosts"                validate:"omitempty,dive,required"`    //nolint:lll,tagalign
}

type Route struct {
	Path       string             `json:"path"        yaml:"path"        validate:"required"`                //nolint:lll,tagalign
	PathParams []ParameterMatcher `json:"path_params" yaml:"path_params" validate:"omitempty,dive,required"` //nolint:lll,tagalign
}

func (r *Route) DeepCopyInto(out *Route) {
	*out = *r

	out.PathParams = slices.Clone(r.PathParams)
}

type ParameterMatcher struct {
	Name  string `json:"name"  yaml:"name"  validate:"required,ne=*"`                   //nolint:tagalign
	Value string `json:"value" yaml:"value" validate:"required"`                        //nolint:tagalign
	Type  string `json:"type"  yaml:"type"  validate:"required,oneof=exact glob regex"` //nolint:tagalign
}

type HostMatcher struct {
	Value string `json:"value" yaml:"value" validate:"required"`                                 //nolint:tagalign
	Type  string `json:"type"  yaml:"type"  validate:"required,oneof=exact glob regex wildcard"` //nolint:tagalign
}

func (m *Matcher) DeepCopyInto(out *Matcher) {
	var withBacktracking *bool

	if m.BacktrackingEnabled != nil {
		value := *m.BacktrackingEnabled
		withBacktracking = &value
	}

	out.Scheme = m.Scheme
	out.BacktrackingEnabled = withBacktracking
	out.Methods = slices.Clone(m.Methods)
	out.Hosts = slices.Clone(m.Hosts)

	out.Routes = make([]Route, len(m.Routes))
	for i, route := range m.Routes {
		route.DeepCopyInto(&out.Routes[i])
	}
}

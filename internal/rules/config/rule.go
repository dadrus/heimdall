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
	"github.com/dadrus/heimdall/internal/config"
)

type EncodedSlashesHandling string

const (
	EncodedSlashesOff      EncodedSlashesHandling = "off"
	EncodedSlashesOn       EncodedSlashesHandling = "on"
	EncodedSlashesNoDecode EncodedSlashesHandling = "no_decode"
)

type Rule struct {
	ID                     string                   `json:"id"                    yaml:"id"`
	EncodedSlashesHandling EncodedSlashesHandling   `json:"allow_encoded_slashes" yaml:"allow_encoded_slashes" validate:"omitempty,oneof=off on no_decode"` //nolint:lll,tagalign
	RuleMatcher            Matcher                  `json:"match"                 yaml:"match"`
	Backend                *Backend                 `json:"forward_to"            yaml:"forward_to"`
	Methods                []string                 `json:"methods"               yaml:"methods"`
	Execute                []config.MechanismConfig `json:"execute"               yaml:"execute"`
	ErrorHandler           []config.MechanismConfig `json:"on_error"              yaml:"on_error"`
}

func (in *Rule) DeepCopyInto(out *Rule) {
	*out = *in
	out.RuleMatcher = in.RuleMatcher

	if in.Backend != nil {
		in, out := in.Backend, out.Backend

		in.DeepCopyInto(out)
	}

	if in.Methods != nil {
		in, out := &in.Methods, &out.Methods

		*out = make([]string, len(*in))
		copy(*out, *in)
	}

	if in.Execute != nil {
		in, out := &in.Execute, &out.Execute

		*out = make([]config.MechanismConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}

	if in.ErrorHandler != nil {
		in, out := &in.ErrorHandler, &out.ErrorHandler

		*out = make([]config.MechanismConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

func (in *Rule) DeepCopy() *Rule {
	if in == nil {
		return nil
	}

	out := new(Rule)
	in.DeepCopyInto(out)

	return out
}

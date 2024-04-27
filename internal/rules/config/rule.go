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
	"crypto"
	"fmt"

	"github.com/goccy/go-json"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
)

type Rule struct {
	ID                     string                   `json:"id"                    yaml:"id"                    validate:"required"`                         //nolint:lll,tagalign
	EncodedSlashesHandling EncodedSlashesHandling   `json:"allow_encoded_slashes" yaml:"allow_encoded_slashes" validate:"omitempty,oneof=off on no_decode"` //nolint:lll,tagalign
	Matcher                Matcher                  `json:"match"                 yaml:"match"                 validate:"required"`                         //nolint:lll,tagalign
	Backend                *Backend                 `json:"forward_to"            yaml:"forward_to"            validate:"omitnil"`                          //nolint:lll,tagalign
	Execute                []config.MechanismConfig `json:"execute"               yaml:"execute"               validate:"gt=0,dive,required"`               //nolint:lll,tagalign
	ErrorHandler           []config.MechanismConfig `json:"on_error"              yaml:"on_error"`
}

func (r *Rule) Hash() ([]byte, error) {
	rawRuleConfig, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create hash", heimdall.ErrInternal)
	}

	md := crypto.SHA256.New()
	md.Write(rawRuleConfig)

	return md.Sum(nil), nil
}

func (r *Rule) DeepCopyInto(out *Rule) {
	*out = *r

	inm, outm := &r.Matcher, &out.Matcher
	inm.DeepCopyInto(outm)

	if r.Backend != nil {
		in, out := r.Backend, out.Backend

		in.DeepCopyInto(out)
	}

	if r.Execute != nil {
		in, out := &r.Execute, &out.Execute

		*out = make([]config.MechanismConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}

	if r.ErrorHandler != nil {
		in, out := &r.ErrorHandler, &out.ErrorHandler

		*out = make([]config.MechanismConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

func (r *Rule) DeepCopy() *Rule {
	if r == nil {
		return nil
	}

	out := new(Rule)
	r.DeepCopyInto(out)

	return out
}

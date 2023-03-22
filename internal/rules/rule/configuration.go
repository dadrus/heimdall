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

package rule

import (
	"strings"
	"time"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type SetMeta struct {
	Hash    []byte    `json:"-" yaml:"-"`
	Source  string    `json:"-" yaml:"-"`
	ModTime time.Time `json:"-" yaml:"-"`
}

type SetConfiguration struct {
	SetMeta

	Version string          `json:"version" yaml:"version"`
	Name    string          `json:"name" yaml:"name"`
	Rules   []Configuration `json:"rules" yaml:"rules"`
}

func (rs SetConfiguration) VerifyPathPrefix(prefix string) error {
	for _, rule := range rs.Rules {
		if strings.HasPrefix(rule.RuleMatcher.URL, "/") &&
			// only path is specified
			!strings.HasPrefix(rule.RuleMatcher.URL, prefix) ||
			// patterns are specified before the path
			// There should be a better way to check it
			!strings.Contains(rule.RuleMatcher.URL, prefix) {
			return errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"path prefix validation failed for rule ID=%s")
		}
	}

	return nil
}

type Configuration struct {
	ID           string                   `json:"id" yaml:"id"`
	RuleMatcher  Matcher                  `json:"match" yaml:"match"`
	Upstream     string                   `json:"upstream" yaml:"upstream"`
	Methods      []string                 `json:"methods" yaml:"methods"`
	Execute      []config.MechanismConfig `json:"execute" yaml:"execute"`
	ErrorHandler []config.MechanismConfig `json:"on_error" yaml:"on_error"`
}

func (in *Configuration) DeepCopyInto(out *Configuration) {
	*out = *in
	out.RuleMatcher = in.RuleMatcher

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

func (in *Configuration) DeepCopy() *Configuration {
	if in == nil {
		return nil
	}

	out := new(Configuration)
	in.DeepCopyInto(out)

	return out
}

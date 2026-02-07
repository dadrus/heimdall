// Copyright 2025 Dimitrij Drus <dadrus@gmx.de>
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

package v1beta1

import "github.com/dadrus/heimdall/internal/config"

type Step struct {
	ID                string                 `json:"id,omitempty"             yaml:"id,omitempty"`
	Condition         *string                `json:"if,omitempty"             yaml:"if,omitempty"`
	AuthenticatorRef  string                 `json:"authenticator,omitempty"  yaml:"authenticator,omitempty"`
	AuthorizerRef     string                 `json:"authorizer,omitempty"     yaml:"authorizer,omitempty"`
	ContextualizerRef string                 `json:"contextualizer,omitempty" yaml:"contextualizer,omitempty"`
	FinalizerRef      string                 `json:"finalizer,omitempty"      yaml:"finalizer,omitempty"`
	ErrorHandlerRef   string                 `json:"error_handler,omitempty"  yaml:"error_handler,omitempty"`
	Principal         *string                `json:"principal,omitempty"      yaml:"principal,omitempty"`
	Config            config.MechanismConfig `json:"config,omitempty"         yaml:"config,omitempty"`
}

type MechanismReference struct {
	Kind string
	Name string
}

func (s *Step) MechanismReference() MechanismReference {
	switch {
	case len(s.AuthenticatorRef) != 0:
		return MechanismReference{Kind: "authenticator", Name: s.AuthenticatorRef}
	case len(s.AuthorizerRef) != 0:
		return MechanismReference{Kind: "authorizer", Name: s.AuthorizerRef}
	case len(s.ContextualizerRef) != 0:
		return MechanismReference{Kind: "contextualizer", Name: s.ContextualizerRef}
	case len(s.FinalizerRef) != 0:
		return MechanismReference{Kind: "finalizer", Name: s.FinalizerRef}
	case len(s.ErrorHandlerRef) != 0:
		return MechanismReference{Kind: "error_handler", Name: s.ErrorHandlerRef}
	default:
		return MechanismReference{Kind: "unknown", Name: ""}
	}
}

func (s *Step) DeepCopyInto(out *Step) {
	*out = *s

	if s.Condition != nil {
		in, out := &s.Condition, &out.Condition
		*out = new(string)
		**out = **in
	}

	if s.Principal != nil {
		in, out := &s.Principal, &out.Principal
		*out = new(string)
		**out = **in
	}

	s.Config.DeepCopyInto(&out.Config)
}

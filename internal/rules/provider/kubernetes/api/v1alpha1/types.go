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

package v1alpha1

//go:generate controller-gen object paths=$GOFILE

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/dadrus/heimdall/internal/rules/config"
)

// +kubebuilder:object:generate=true
type RuleSetSpec struct {
	AuthClassName string        `json:"authClassName"` //nolint:tagliatelle
	Rules         []config.Rule `json:"rules"`
}

func (in *RuleSetSpec) String() string {
	if in == nil {
		return "nil"
	}

	return strings.Join([]string{
		`&RuleSetSpec{`,
		fmt.Sprintf("AuthClassName: %v", in.AuthClassName) + `,`,
		fmt.Sprintf("Rules: %v", in.Rules),
		`}`,
	}, "")
}

// +kubebuilder:object:generate=true
type RuleSet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec RuleSetSpec `json:"spec"`
}

func (in *RuleSet) String() string {
	if in == nil {
		return "nil"
	}

	return strings.Join([]string{
		`&RuleSet{`,
		fmt.Sprintf("%v", in.TypeMeta.String()) + `,`,
		fmt.Sprintf("%v", in.ObjectMeta.String()) + `,`,
		fmt.Sprintf("%v", in.Spec.String()),
		`}`,
	}, "")
}

func (in *RuleSet) DeepCopyObject() runtime.Object { return in.DeepCopy() }

// +kubebuilder:object:generate=true
type RuleSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []RuleSet `json:"items"`
}

func (in *RuleSetList) DeepCopyObject() runtime.Object { return in.DeepCopy() }

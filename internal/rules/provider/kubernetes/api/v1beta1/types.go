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

package v1beta1

//go:generate controller-gen object paths=$GOFILE

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes/scheme"

	"github.com/dadrus/heimdall/internal/rules/api/v1beta1"
)

func init() { //nolint: gochecknoinits
	schemeBuilder := runtime.NewSchemeBuilder(func(scheme *runtime.Scheme) error {
		scheme.AddKnownTypes(GroupVersion, &RuleSet{}, &RuleSetList{})
		metav1.AddToGroupVersion(scheme, GroupVersion)

		return nil
	})
	utilruntime.Must(schemeBuilder.AddToScheme(scheme.Scheme))
}

var GroupVersion = schema.GroupVersion{ //nolint: gochecknoglobals
	Group:   "heimdall.dadrus.github.com",
	Version: "v1beta1",
}

const (
	ResourceName     = "RuleSet"
	ResourceListName = "RuleSets"
)

// RuleSetSpec is the actual ruleset definition
// +kubebuilder:object:generate=true
// nolint: godoclint
type RuleSetSpec struct {
	AuthClassName string         `json:"authClassName"` //nolint:tagliatelle
	Rules         []v1beta1.Rule `json:"rules"`
}

// RuleSetStatus describes the deployment status of a ruleset
// +kubebuilder:object:generate=true
// nolint: godoclint
type RuleSetStatus struct {
	ActiveIn   string             `json:"activeIn"` // nolint: tagliatelle
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// RuleSet defines the kubernetes custom resource to describe rulesets
// +kubebuilder:object:generate=true
// +kubebuilder:object:root=true
// nolint: godoclint
type RuleSet struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitzero"`

	Spec   RuleSetSpec   `json:"spec"`
	Status RuleSetStatus `json:"status"`
}

func (rs *RuleSet) AsConfig() *v1beta1.RuleSet {
	return &v1beta1.RuleSet{
		MetaData: v1beta1.MetaData{
			Source:  fmt.Sprintf("%s:%s:%s", "kubernetes", rs.Namespace, rs.UID),
			ModTime: rs.CreationTimestamp.Time,
		},
		Version: "1beta1",
		Name:    rs.Name,
		Rules:   rs.Spec.Rules,
	}
}

// RuleSetList defines the list of RuleSet resources
// +kubebuilder:object:generate=true
// +kubebuilder:object:root=true
// nolint: godoclint
type RuleSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`

	Items []RuleSet `json:"items"`
}

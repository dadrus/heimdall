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

package v1alpha4

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

type (
	Client interface {
		Repository(namespace string) Repository
	}

	client struct {
		cl rest.Interface
	}
)

func NewClient(conf *rest.Config) (Client, error) {
	schemeBuilder := runtime.NewSchemeBuilder(func(scheme *runtime.Scheme) error {
		scheme.AddKnownTypes(GroupVersion, &RuleSet{}, &RuleSetList{})
		metav1.AddToGroupVersion(scheme, GroupVersion)

		return nil
	})
	if err := schemeBuilder.AddToScheme(scheme.Scheme); err != nil {
		return nil, err
	}

	config := *conf
	config.GroupVersion = &GroupVersion
	config.APIPath = "/apis"
	config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	config.UserAgent = rest.DefaultKubernetesUserAgent()

	cl, err := rest.RESTClientFor(&config)
	if err != nil {
		return nil, err
	}

	return &client{cl: cl}, nil
}

func (c *client) Repository(namespace string) Repository {
	return &ruleSetRepository{
		cl: c.cl,
		ns: namespace,
	}
}

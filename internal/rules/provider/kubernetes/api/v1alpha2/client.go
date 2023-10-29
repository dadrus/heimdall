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

package v1alpha2

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

const (
	GroupName    = "heimdall.dadrus.github.com"
	GroupVersion = "v1alpha2"
)

func addKnownTypes(gv schema.GroupVersion) func(scheme *runtime.Scheme) error {
	return func(scheme *runtime.Scheme) error {
		scheme.AddKnownTypes(gv, &RuleSet{}, &RuleSetList{})
		metav1.AddToGroupVersion(scheme, gv)

		return nil
	}
}

type RuleSetRepository interface {
	List(ctx context.Context, opts metav1.ListOptions) (*RuleSetList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	UpdateStatus(ctx context.Context, rs *RuleSet, opts metav1.UpdateOptions) (*RuleSet, error)
}

type Client interface {
	RuleSetRepository(namespace string) RuleSetRepository
}

func NewClient(conf *rest.Config) (Client, error) {
	gv := schema.GroupVersion{Group: GroupName, Version: GroupVersion}

	schemeBuilder := runtime.NewSchemeBuilder(addKnownTypes(gv))
	if err := schemeBuilder.AddToScheme(scheme.Scheme); err != nil {
		return nil, err
	}

	config := *conf
	config.ContentConfig.GroupVersion = &gv
	config.APIPath = "/apis"
	config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	config.UserAgent = rest.DefaultKubernetesUserAgent()

	cl, err := rest.RESTClientFor(&config)
	if err != nil {
		return nil, err
	}

	return &client{cl: cl}, nil
}

type client struct {
	cl rest.Interface
}

func (c *client) RuleSetRepository(namespace string) RuleSetRepository {
	return &repository{
		cl: c.cl,
		ns: namespace,
	}
}

type repository struct {
	cl rest.Interface
	ns string
}

func (r *repository) List(ctx context.Context, opts metav1.ListOptions) (*RuleSetList, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}

	result := &RuleSetList{}
	err := r.cl.Get().
		Namespace(r.ns).
		Resource("rulesets").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)

	return result, err
}

func (r *repository) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}

	opts.Watch = true

	return r.cl.Get().
		Namespace(r.ns).
		Resource("rulesets").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

func (r *repository) UpdateStatus(ctx context.Context, rs *RuleSet, opts metav1.UpdateOptions) (*RuleSet, error) {
	result := &RuleSet{}
	err := r.cl.Patch(types.JSONPatchType).
		Namespace(r.ns).
		Resource("rulesets").
		Name(rs.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(rs).
		Do(ctx).
		Into(result)

	return result, err
}

// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
)

type object interface {
	metav1.Object
	runtime.Object
}

type Patch interface {
	ResourceName() string
	ResourceNamespace() string
	Type() types.PatchType
	Data() ([]byte, error)
}

//go:generate mockery --name RuleSetRepository --structname RuleSetRepositoryMock

type RuleSetRepository interface {
	List(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Get(ctx context.Context, key types.NamespacedName, opts metav1.GetOptions) (*RuleSet, error)
	PatchStatus(ctx context.Context, patch Patch, opts metav1.PatchOptions) (*RuleSet, error)
}

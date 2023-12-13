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

package v1alpha3

import (
	"github.com/goccy/go-json"
	"github.com/wI2L/jsondiff"
	"k8s.io/apimachinery/pkg/types"
)

type jsonPatch struct {
	patchType            types.PatchType
	from                 object
	to                   object
	enableOptimisticLock bool
}

func (p *jsonPatch) Type() types.PatchType { return p.patchType }

func (p *jsonPatch) Data() ([]byte, error) {
	original := p.from
	modified := p.to

	if p.enableOptimisticLock {
		original = p.from.DeepCopyObject().(object) // nolint: forcetypeassert
		modified = p.to.DeepCopyObject().(object)   // nolint: forcetypeassert

		modified.SetResourceVersion(original.GetResourceVersion())
		original.SetResourceVersion("")
	}

	patch, err := jsondiff.Compare(original, modified,
		jsondiff.MarshalFunc(json.Marshal),
		jsondiff.UnmarshalFunc(json.Unmarshal),
		jsondiff.Factorize())
	if err != nil {
		return nil, err
	}

	return json.Marshal(patch)
}

func (p *jsonPatch) ResourceName() string      { return p.from.GetName() }
func (p *jsonPatch) ResourceNamespace() string { return p.from.GetNamespace() }

func NewJSONPatch(from, to object, withOptimisticLock bool) Patch {
	return &jsonPatch{patchType: types.JSONPatchType, from: from, to: to, enableOptimisticLock: withOptimisticLock}
}

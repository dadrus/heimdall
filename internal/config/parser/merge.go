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

package parser

import (
	"fmt"
	"reflect"

	"github.com/knadh/koanf/maps"
)

func merge(dest, src any) any {
	if dest == nil {
		return cleanSuffix(src)
	}

	vDst := reflect.ValueOf(dest)
	vSrc := reflect.ValueOf(src)

	switch vDst.Kind() {
	case reflect.Map:
		if vSrc.Type() != vDst.Type() {
			panic(fmt.Sprintf("Cannot merge %s and %s. Types are different: %s - %s", dest, src, vDst.Type(), vSrc.Type()))
		}

		// nolint: forcetypeassert
		return mergeMaps(dest.(map[string]any), src.(map[string]any))
	case reflect.Slice:
		// nolint: forcetypeassert
		return mergeSlices(dest, src)
	default:
		// any other (primitive) type
		// overriding
		return src
	}
}

func mergeSlices(dest, src any) any {
	vDst := reflect.ValueOf(dest)
	vSrc := reflect.ValueOf(src)

	if vDst.Len() < vSrc.Len() {
		oldDest := dest
		vDst = reflect.MakeSlice(vDst.Type(), vSrc.Len(), vSrc.Len())

		vOldDst := reflect.ValueOf(oldDest)
		reflect.Copy(vDst, vOldDst)
	}

	for i := range vSrc.Len() {
		// getting the actual item here as the value returned by Index
		// might be {interface{} | some-type}, which will result in
		// a panic while calling dstIdx.Set as vDst is typically {[]some-type}
		item := vSrc.Index(i).Interface()
		dstIdx := vDst.Index(i)

		avail := vDst.Index(i)
		if avail.IsZero() {
			dstIdx.Set(reflect.ValueOf(item))
		} else if item != nil {
			dstIdx.Set(reflect.ValueOf(merge(avail, item)))
		}
	}

	return vDst.Interface()
}

func mergeMaps(dest, src map[string]any) map[string]any {
	for k, v := range maps.Unflatten(src, ".") {
		old := dest[k]
		if old == nil {
			dest[k] = v
		} else {
			dest[k] = merge(old, v)
		}
	}

	return dest
}

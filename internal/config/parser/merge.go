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
)

func merge(dest, src any) any {
	if dest == nil {
		return cleanSuffix(src)
	}

	vDst := reflect.ValueOf(dest)
	vSrc := reflect.ValueOf(src)

	// nolint: exhaustive
	switch vDst.Kind() {
	case reflect.Map:
		if vSrc.Type() != vDst.Type() {
			panic(fmt.Sprintf("Cannot merge %s and %s. Types are different: %s - %s", dest, src, vDst.Type(), vSrc.Type()))
		}

		// nolint: forcetypeassert
		return mergeMaps(dest.(map[string]any), src.(map[string]any))
	case reflect.Slice:
		if vSrc.Type() != vDst.Type() {
			panic(fmt.Sprintf("Cannot merge %s and %s. Types are different: %s - %s", dest, src, vDst.Type(), vSrc.Type()))
		}

		// nolint: forcetypeassert
		return mergeSlices(dest.([]any), src.([]any))
	default:
		// any other (primitive) type
		// overriding
		return src
	}
}

func mergeSlices(dest, src []any) []any {
	if len(dest) < len(src) {
		oldDest := dest
		dest = make([]any, len(src))

		copy(dest, oldDest)
	}

	for i, v := range src {
		avail := dest[i]
		if avail == nil {
			dest[i] = v
		} else if v != nil {
			dest[i] = merge(avail, v)
		}
	}

	return dest
}

func mergeMaps(dest, src map[string]any) map[string]any {
	for k, v := range src {
		old := dest[k]
		if old == nil {
			dest[k] = v
		} else {
			dest[k] = merge(old, v)
		}
	}

	return dest
}

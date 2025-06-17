// Copyright 2022-2025 Dimitrij Drus <dadrus@gmx.de>
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

package radixtree

// LookupMatcher is used for additional checks while performing the lookup of values in the spanned tree.
type LookupMatcher[V any] interface {
	// Match should return true if the value should be returned by the lookup.
	Match(value V, keys, values []string) bool
}

// The LookupMatcherFunc type is an adapter to allow the use of ordinary functions as match functions.
// If f is a function with the appropriate signature, LookupMatcherFunc(f) is a [LookupMatcher]
// that calls f.
type LookupMatcherFunc[V any] func(value V, keys, values []string) bool

// Match calls f(value).
func (f LookupMatcherFunc[V]) Match(value V, keys, values []string) bool {
	return f(value, keys, values)
}

// ValueMatcher is used for additional checks while deleting of values in the spanned tree.
type ValueMatcher[V any] interface {
	// Match should return true if the value should be deleted from the tree.
	Match(value V) bool
}

// The ValueMatcherFunc type is an adapter to allow the use of ordinary functions as match functions.
// If f is a function with the appropriate signature, ValueMatcherFunc(f) is a [ValueMatcher]
// that calls f.
type ValueMatcherFunc[V any] func(value V) bool

// Match calls f(value).
func (f ValueMatcherFunc[V]) Match(value V) bool {
	return f(value)
}

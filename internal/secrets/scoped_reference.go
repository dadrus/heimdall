// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package secrets

type referenceScope string

const (
	referenceScopeInternal referenceScope = "internal"
	referenceScopeRule     referenceScope = "rule"
)

type scopedReference struct {
	Reference

	namespace string
	scope     referenceScope
}

type referenceFactory func(Reference) scopedReference

func internalRef(ref Reference) scopedReference {
	return scopedReference{
		Reference: ref,
		scope:     referenceScopeInternal,
	}
}

func ruleRef(ref Reference, namespace string) scopedReference {
	return scopedReference{
		Reference: ref,
		namespace: namespace,
		scope:     referenceScopeRule,
	}
}

func namespacedRuleRef(namespace string) referenceFactory {
	return func(ref Reference) scopedReference {
		return ruleRef(ref, namespace)
	}
}

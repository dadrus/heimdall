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

package x

func IfThenElse[T any](c bool, thenVal, elseVal T) T {
	if c {
		return thenVal
	}

	return elseVal
}

func IfThenElseExec[T any](c bool, thenFunc func() T, elseFunc func() T) T {
	if c {
		return thenFunc()
	}

	return elseFunc()
}

func IfThenElseExecErr[T any](c bool, thenFunc func() (T, error), elseFunc func() (T, error)) (T, error) {
	if c {
		return thenFunc()
	}

	return elseFunc()
}

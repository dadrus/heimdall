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

package heimdall

import (
	"errors"
	"reflect"
)

var (
	ErrArgument             = errors.New("argument error")
	ErrAuthentication       = errors.New("authentication error")
	ErrAuthorization        = errors.New("authorization error")
	ErrCommunication        = errors.New("communication error")
	ErrCommunicationTimeout = errors.New("communication timeout error")
	ErrConfiguration        = errors.New("configuration error")
	ErrInternal             = errors.New("internal error")
	ErrNoRuleFound          = errors.New("no rule found")
)

type RedirectError struct {
	Message    string
	Code       int
	RedirectTo string
}

func (e *RedirectError) Error() string { return e.Message }

func (e *RedirectError) Is(target error) bool { return reflect.TypeOf(e) == reflect.TypeOf(target) }

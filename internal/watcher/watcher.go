// Copyright 2024 Dimitrij Drus <dadrus@gmx.de>
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

package watcher

import "github.com/rs/zerolog"

//go:generate mockery --name ChangeListener --structname ChangeListenerMock --inpackage --testonly

type ChangeListener interface {
	OnChanged(logger zerolog.Logger)
}

//go:generate mockery --name Watcher --structname WatcherMock

type Watcher interface {
	Add(path string, cl ChangeListener) error
}

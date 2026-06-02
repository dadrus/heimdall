// Copyright 2026 Dimitrij Drus
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package fswatch

// Op describes the type of change observed for a path.
type Op uint8

const (
	// OpAdded means that a path was added below a watched directory.
	//
	// OpAdded is emitted only for entries below watched directories.
	OpAdded Op = iota + 1

	// OpChanged means that the content or target of a watched path changed.
	//
	// For files, this means the watched file changed.
	// For directories, this can either mean a child changed or that the
	// watched directory itself was rebound, e.g. by a symlink target switch.
	OpChanged

	// OpDeleted means that a watched path or an entry below a watched directory
	// was removed or is no longer accessible.
	OpDeleted
)

func (o Op) String() string {
	switch o {
	case OpAdded:
		return "added"
	case OpChanged:
		return "changed"
	case OpDeleted:
		return "deleted"
	default:
		return "unknown"
	}
}

// Event is a normalized filesystem event.
//
// For file roots, Path is the watched file path.
// For directory roots, Path is either an affected child path or the watched
// directory path itself when the directory target changed.
type Event struct {
	Path string
	Op   Op
}

// EventHandler receives normalized filesystem events.
type EventHandler interface {
	HandleEvent(evt Event) error
}

// EventHandlerFunc adapts a function to EventHandler.
type EventHandlerFunc func(evt Event) error

func (f EventHandlerFunc) HandleEvent(evt Event) error {
	return f(evt)
}

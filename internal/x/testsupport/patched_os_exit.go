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

package testsupport

import (
	"os"
	"sync"
	"testing"

	"github.com/undefinedlabs/go-mpatch"
)

type PatchedOSExit struct {
	mutex  sync.RWMutex
	called bool
	code   int

	patchFunc *mpatch.Patch
}

func (p *PatchedOSExit) Called() bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return p.called
}

func (p *PatchedOSExit) Code() int {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return p.code
}

func PatchOSExit(t *testing.T, mockOSExitImpl func(int)) (*PatchedOSExit, error) {
	t.Helper()

	patchedExit := new(PatchedOSExit)

	var err error

	patchedExit.patchFunc, err = mpatch.PatchMethod(os.Exit, func(code int) {
		patchedExit.mutex.Lock()
		patchedExit.called = true
		patchedExit.code = code
		patchedExit.mutex.Unlock()

		mockOSExitImpl(code)
	})

	t.Cleanup(func() {
		if patchedExit.patchFunc != nil {
			_ = patchedExit.patchFunc.Unpatch()
		}
	})

	return patchedExit, err
}

package testsupport

import (
	"os"
	"testing"

	"github.com/undefinedlabs/go-mpatch"
)

type PatchedOSExit struct {
	Called bool
	Code   int

	patchFunc *mpatch.Patch
}

func PatchOSExit(t *testing.T, mockOSExitImpl func(int)) (*PatchedOSExit, error) {
	t.Helper()

	patchedExit := &PatchedOSExit{Called: false}

	var err error

	patchedExit.patchFunc, err = mpatch.PatchMethod(os.Exit, func(code int) {
		patchedExit.Called = true
		patchedExit.Code = code

		mockOSExitImpl(code)
	})

	t.Cleanup(func() {
		if patchedExit.patchFunc != nil {
			_ = patchedExit.patchFunc.Unpatch()
		}
	})

	return patchedExit, err
}

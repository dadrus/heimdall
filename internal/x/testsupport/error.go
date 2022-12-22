package testsupport

import "errors"

var (
	ErrTestPurpose  = errors.New("error raised in a test")
	ErrTestPurpose2 = errors.New("another error raised in a test")
)

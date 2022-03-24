package errorsx

import "reflect"

type ForbiddenError struct {
	Message string
	Cause   error
}

func (e *ForbiddenError) Error() string {
	return e.Message
}

func (e *ForbiddenError) Unwrap() error {
	return e.Cause
}

func (e *ForbiddenError) Is(target error) bool {
	return reflect.TypeOf(e) == reflect.TypeOf(target)
}

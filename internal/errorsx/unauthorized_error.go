package errorsx

import "reflect"

type UnauthorizedError struct {
	Message string
	Cause   error
}

func (e *UnauthorizedError) Error() string {
	return e.Message
}

func (e *UnauthorizedError) Unwrap() error {
	return e.Cause
}

func (e *UnauthorizedError) Is(target error) bool {
	return reflect.TypeOf(e) == reflect.TypeOf(target)
}

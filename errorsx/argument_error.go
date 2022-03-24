package errorsx

import "reflect"

type ArgumentError struct {
	Message string
	Cause   error
}

func (e *ArgumentError) Error() string {
	return e.Message
}

func (e *ArgumentError) Unwrap() error {
	return e.Cause
}

func (e *ArgumentError) Is(target error) bool {
	return reflect.TypeOf(e) == reflect.TypeOf(target)
}

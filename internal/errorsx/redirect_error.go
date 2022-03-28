package errorsx

import "reflect"

type RedirectError struct {
	Message    string
	RedirectTo string
	Cause      error
}

func (e *RedirectError) Error() string {
	return e.Message
}

func (e *RedirectError) Unwrap() error {
	return e.Cause
}

func (e *RedirectError) Is(target error) bool {
	return reflect.TypeOf(e) == reflect.TypeOf(target)
}

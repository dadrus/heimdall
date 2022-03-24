package errorsx

import "reflect"

type RemoteCallError struct {
	Message string
	Cause   error
}

func (e *RemoteCallError) Error() string {
	return e.Message
}

func (e *RemoteCallError) Unwrap() error {
	return e.Cause
}

func (e *RemoteCallError) Is(target error) bool {
	return reflect.TypeOf(e) == reflect.TypeOf(target)
}

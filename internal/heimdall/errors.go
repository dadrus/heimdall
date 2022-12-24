package heimdall

import (
	"errors"
	"reflect"
)

var (
	ErrArgument             = errors.New("argument error")
	ErrAuthentication       = errors.New("authentication error")
	ErrAuthorization        = errors.New("authorization error")
	ErrCommunication        = errors.New("communication error")
	ErrCommunicationTimeout = errors.New("communication timeout error")
	ErrConfiguration        = errors.New("configuration error")
	ErrInternal             = errors.New("internal error")
	ErrMethodNotAllowed     = errors.New("method not allowed")
	ErrNoRuleFound          = errors.New("no rule found")
)

type RedirectError struct {
	Message    string
	Code       int
	RedirectTo string
}

func (e *RedirectError) Error() string { return e.Message }

func (e *RedirectError) Is(target error) bool { return reflect.TypeOf(e) == reflect.TypeOf(target) }

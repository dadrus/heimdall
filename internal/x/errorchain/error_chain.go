package errorchain

import (
	"errors"
	"fmt"
	"strings"
)

type element struct {
	err  error
	next *element
}

type ErrorChain struct {
	head *element
	tail *element
}

func New(err error) *ErrorChain {
	chain := &ErrorChain{}

	return chain.CausedBy(err)
}

func NewWithMessage(err error, message string) *ErrorChain {
	chain := &ErrorChain{}

	return chain.CausedBy(fmt.Errorf("%w: %s", err, message))
}

func NewWithMessagef(err error, format string, a ...any) *ErrorChain {
	chain := &ErrorChain{}

	return chain.CausedBy(fmt.Errorf("%w: %s", err, fmt.Sprintf(format, a)))
}

func (e *ErrorChain) Error() string {
	var errs []string

	for c := e.head; c != nil; c = c.next {
		errs = append(errs, c.err.Error())
	}

	return strings.Join(errs, ": ")
}

func (e *ErrorChain) CausedBy(err error) *ErrorChain {
	wrappedError := &element{err: err}

	if e.head == nil {
		e.head = wrappedError
		e.tail = wrappedError

		return e
	}

	e.tail.next = wrappedError
	e.tail = wrappedError

	return e
}

func (e *ErrorChain) Unwrap() error {
	if e.head == nil || e.head.next == nil {
		return nil
	}

	return &ErrorChain{
		head: e.head.next,
		tail: e.tail,
	}
}

func (e *ErrorChain) Is(target error) bool {
	if e.head == nil {
		return false
	}

	return errors.Is(e.head.err, target)
}

func (e *ErrorChain) Errors() []error {
	var errs []error

	for c := e.head; c != nil; c = c.next {
		errs = append(errs, c.err)
	}

	return errs
}

package errorchain

import (
	"errors"
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

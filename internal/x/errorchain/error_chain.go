// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package errorchain

import (
	"encoding/xml"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/goccy/go-json"
	"github.com/iancoleman/strcase"
)

type element struct {
	err     error
	msg     string
	next    *element
	aspects []any
}

type message struct { //nolint:musttag
	XMLName xml.Name `json:"-"`
	Code    string   `json:"code"              xml:"code"`
	Message string   `json:"message,omitempty" xml:"message,omitempty"`
}

// ErrorChain represents a linear causal chain where each error is caused by the next.
type ErrorChain struct { // nolint: errname
	head *element
	tail *element
}

type errorList struct { //nolint:errname
	errs []error
}

// New starts a causal chain with err as its sentinel error.
func New(err error) *ErrorChain {
	chain := &ErrorChain{}

	return chain.causedBy(err, "")
}

// NewWithMessage starts a causal chain with a sentinel error and context.
func NewWithMessage(err error, message string) *ErrorChain {
	chain := &ErrorChain{}

	return chain.causedBy(err, message)
}

// NewWithMessagef starts a causal chain with a sentinel error and formatted context.
func NewWithMessagef(err error, format string, a ...any) *ErrorChain {
	chain := &ErrorChain{}

	return chain.causedBy(err, fmt.Sprintf(format, a...))
}

func (ec *ErrorChain) Error() string {
	var errs []string

	for c := ec.head; c != nil; c = c.next {
		if len(c.msg) == 0 {
			errs = append(errs, c.err.Error())
		} else {
			err := c.err.Error() + ": " + c.msg
			errs = append(errs, err)
		}
	}

	return strings.Join(errs, ": ")
}

// CausedBy appends err as the cause of the preceding error. Use List for independent causes.
func (ec *ErrorChain) CausedBy(err error) *ErrorChain {
	return ec.causedBy(err, "")
}

// List groups independent errors into one visible cause. Nil errors are ignored.
func List(errs ...error) error {
	nonNil := make([]error, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			nonNil = append(nonNil, err)
		}
	}

	switch len(nonNil) {
	case 0:
		return nil
	case 1:
		return nonNil[0]
	default:
		return &errorList{errs: nonNil}
	}
}

func (e *errorList) Error() string {
	messages := make([]string, 0, len(e.errs))
	for _, err := range e.errs {
		messages = append(messages, err.Error())
	}

	return "[" + strings.Join(messages, ", ") + "]"
}

func (e *errorList) Unwrap() []error {
	return e.errs
}

func (ec *ErrorChain) WithAspects(values ...any) *ErrorChain {
	ec.tail.aspects = append(ec.tail.aspects, values...)

	return ec
}

func (ec *ErrorChain) Unwrap() error {
	if ec.head == nil || ec.head.next == nil {
		return nil
	}

	return &ErrorChain{
		head: ec.head.next,
		tail: ec.tail,
	}
}

func (ec *ErrorChain) As(target any) bool {
	if ec.asTarget(target) {
		return true
	}

	return errors.As(ec.head.err, target)
}

func (ec *ErrorChain) Is(target error) bool {
	return errors.Is(ec.head.err, target)
}

func (ec *ErrorChain) Errors() []error {
	var errs []error

	for c := ec.head; c != nil; c = c.next {
		errs = append(errs, c.err)
	}

	return errs
}

func (ec *ErrorChain) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		message{
			Code:    strcase.ToLowerCamel(ec.head.err.Error()),
			Message: ec.firstMessage(),
		})
}

func (ec *ErrorChain) MarshalXML(encoder *xml.Encoder, _ xml.StartElement) error {
	return encoder.Encode(
		message{ //nolint:musttag
			XMLName: xml.Name{Local: "error"},
			Code:    strcase.ToLowerCamel(ec.head.err.Error()),
			Message: ec.firstMessage(),
		})
}

func (ec *ErrorChain) String() string {
	return ec.head.err.Error() + ": " + ec.firstMessage()
}

func (ec *ErrorChain) asTarget(target any) bool {
	if target == nil {
		return false
	}

	val := reflect.ValueOf(target)
	if val.Kind() != reflect.Pointer || val.IsNil() {
		return false
	}

	targetType := val.Type().Elem()
	if targetType.Kind() != reflect.Interface {
		return false
	}

	for _, aspect := range ec.head.aspects {
		if aspect == nil {
			continue
		}

		aspectValue := reflect.ValueOf(aspect)
		if !aspectValue.Type().AssignableTo(targetType) {
			continue
		}

		val.Elem().Set(aspectValue)

		return true
	}

	return false
}

func (ec *ErrorChain) causedBy(err error, msg string) *ErrorChain {
	wrappedError := &element{err: err, msg: msg}

	if ec.head == nil {
		ec.head = wrappedError
		ec.tail = wrappedError

		return ec
	}

	ec.tail.next = wrappedError
	ec.tail = wrappedError

	return ec
}

func (ec *ErrorChain) firstMessage() string {
	current := ec.head

	for current != nil {
		if len(current.msg) != 0 {
			return current.msg
		}

		if chained, ok := current.err.(*ErrorChain); ok { //nolint: errorlint
			msg := chained.firstMessage()
			if msg != chained.Error() {
				return msg
			}
		}

		if current.next == nil {
			return current.err.Error()
		}

		current = current.next
	}

	return "no details available"
}

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
	err  error
	msg  string
	next *element
}

// nolint
type ErrorChain struct {
	head    *element
	tail    *element
	context any
}

func New(err error) *ErrorChain {
	chain := &ErrorChain{}

	return chain.causedBy(err, "")
}

func NewWithMessage(err error, message string) *ErrorChain {
	chain := &ErrorChain{}

	return chain.causedBy(err, message)
}

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
			errs = append(errs, fmt.Sprintf("%s: %s", c.err.Error(), c.msg))
		}
	}

	return strings.Join(errs, ": ")
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

func (ec *ErrorChain) CausedBy(err error) *ErrorChain {
	return ec.causedBy(err, "")
}

func (ec *ErrorChain) WithErrorContext(context any) *ErrorChain {
	ec.context = context

	return ec
}

func (ec *ErrorChain) Unwrap() error {
	if ec.head == nil || ec.head.next == nil {
		return nil
	}

	return &ErrorChain{
		head:    ec.head.next,
		tail:    ec.tail,
		context: ec.context,
	}
}

func (ec *ErrorChain) Is(target error) bool {
	if ec.head == nil {
		return false
	}

	return errors.Is(ec.head.err, target)
}

func (ec *ErrorChain) As(target any) bool {
	if ec.head == nil {
		return false
	}

	if ec.asTarget(target) {
		return true
	}

	return errors.As(ec.head.err, target)
}

func (ec *ErrorChain) asTarget(target any) bool {
	if ec.context == nil {
		return false
	}

	val := reflect.ValueOf(target)
	targetType := val.Type().Elem()

	if targetType.Kind() != reflect.Interface {
		return false
	}

	if reflect.TypeOf(ec.context).AssignableTo(targetType) {
		val.Elem().Set(reflect.ValueOf(ec.context))

		return true
	}

	return false
}

func (ec *ErrorChain) ErrorContext() any {
	return ec.context
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
			Message: ec.head.msg,
		})
}

func (ec *ErrorChain) MarshalXML(encoder *xml.Encoder, start xml.StartElement) error {
	return encoder.Encode(
		message{
			XMLName: xml.Name{Local: "error"},
			Code:    strcase.ToLowerCamel(ec.head.err.Error()),
			Message: ec.head.msg,
		})
}

type message struct {
	XMLName xml.Name `json:"-"`
	Code    string   `xml:"code" json:"code"`
	Message string   `xml:"message,omitempty" json:"message,omitempty"`
}

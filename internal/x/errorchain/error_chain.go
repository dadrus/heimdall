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

type errorChain struct { // nolint: errname
	head    *element
	tail    *element
	context any
}

func New(err error) *errorChain {
	chain := &errorChain{}

	return chain.causedBy(err, "")
}

func NewWithMessage(err error, message string) *errorChain {
	chain := &errorChain{}

	return chain.causedBy(err, message)
}

func NewWithMessagef(err error, format string, a ...any) *errorChain {
	chain := &errorChain{}

	return chain.causedBy(err, fmt.Sprintf(format, a...))
}

func (ec *errorChain) Error() string {
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

func (ec *errorChain) causedBy(err error, msg string) *errorChain {
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

func (ec *errorChain) CausedBy(err error) *errorChain {
	return ec.causedBy(err, "")
}

func (ec *errorChain) WithErrorContext(context any) *errorChain {
	ec.context = context

	return ec
}

func (ec *errorChain) Unwrap() error {
	if ec.head == nil || ec.head.next == nil {
		return nil
	}

	return &errorChain{
		head:    ec.head.next,
		tail:    ec.tail,
		context: ec.context,
	}
}

func (ec *errorChain) Is(target error) bool {
	if ec.head == nil {
		return false
	}

	return errors.Is(ec.head.err, target)
}

func (ec *errorChain) As(target any) bool {
	if ec.head == nil {
		return false
	}

	if ec.asTarget(target) {
		return true
	}

	return errors.As(ec.head.err, target)
}

func (ec *errorChain) asTarget(target any) bool {
	if ec.context == nil {
		return false
	}

	val := reflect.ValueOf(target)
	targetType := val.Type().Elem()

	if targetType.Kind() != reflect.Interface || !reflect.TypeOf(ec.context).AssignableTo(targetType) {
		return false
	}

	val.Elem().Set(reflect.ValueOf(ec.context))

	return true
}

func (ec *errorChain) ErrorContext() any {
	return ec.context
}

func (ec *errorChain) Errors() []error {
	var errs []error

	for c := ec.head; c != nil; c = c.next {
		errs = append(errs, c.err)
	}

	return errs
}

func (ec *errorChain) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		message{
			Code:    strcase.ToLowerCamel(ec.head.err.Error()),
			Message: ec.head.msg,
		})
}

func (ec *errorChain) MarshalXML(encoder *xml.Encoder, start xml.StartElement) error {
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

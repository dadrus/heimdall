package matcher

import "errors"

type ErrorDescriptor struct {
	Errors    []error
	HandlerID string
}

func (ed ErrorDescriptor) Matches(err error) bool {
	if !ed.matchesError(err) {
		return false
	}

	if !ed.matchesHandlerID(err) {
		return false
	}

	return true
}

func (ed ErrorDescriptor) matchesHandlerID(err error) bool {
	if len(ed.HandlerID) == 0 {
		return true
	}

	var handlerIdentifier interface{ HandlerID() string }
	ok := errors.As(err, &handlerIdentifier)

	return ok && ed.HandlerID == handlerIdentifier.HandlerID()
}

func (ed ErrorDescriptor) matchesError(err error) bool {
	for _, v := range ed.Errors {
		if errors.Is(err, v) {
			return true
		}
	}

	return false
}

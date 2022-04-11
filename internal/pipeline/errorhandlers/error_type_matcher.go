package errorhandlers

import (
	"errors"
)

type ErrorTypeMatcher []error

func (etm ErrorTypeMatcher) Match(err error) bool {
	for _, v := range etm {
		if errors.Is(err, v) {
			return true
		}
	}

	return false
}

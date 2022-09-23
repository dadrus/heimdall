package matcher

type ErrorMatcher []ErrorDescriptor

func (etm ErrorMatcher) Match(err error) bool {
	for _, v := range etm {
		if v.Matches(err) {
			return true
		}
	}

	return false
}

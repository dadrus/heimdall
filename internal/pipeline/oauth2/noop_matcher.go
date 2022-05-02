package oauth2

type NoopMatcher struct{}

func (NoopMatcher) Match(_ []string) error {
	return nil
}

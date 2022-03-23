package pipeline

import "net/url"

type RuleMatcher interface {
	Match(url *url.URL) (Rule, error)
}

package oauth2

import "errors"

var ErrScopeMatch = errors.New("scope matching error")

type ScopesMatcher interface {
	Match(scopes []string) error
}

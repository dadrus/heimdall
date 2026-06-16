package oauth2

import "net/http"

type ChallengePolicy struct {
	Realm                 string
	ErrorURI              string
	IncludeErrorDetails   bool
	IncludeRequiredScopes bool
	DPoPAlgorithms        []string
}

type Challenge struct {
	StatusCode int
	Headers    http.Header
}

type Challenger interface {
	Challenge(policy ChallengePolicy) (*Challenge, error)
}

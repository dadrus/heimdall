package oauth2

type ScopesMatcher interface {
	Match(scopes []string) error
}

package authenticators

type AuthDataGetter interface {
	GetAuthData(s AuthDataSource) (string, error)
}

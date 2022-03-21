package extractors

type AuthDataExtractor interface {
	Extract(s AuthDataSource) (string, error)
}

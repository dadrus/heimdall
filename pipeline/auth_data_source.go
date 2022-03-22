package pipeline

type AuthDataSource interface {
	Header(key string) string
	Cookie(key string) string
	Query(key string) string
	Form(key string) string
}

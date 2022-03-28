package handler

type RequestContext interface {
	Header(key string) string
	Cookie(key string) string
	Query(key string) string
	Form(key string) string
	Body() []byte
}

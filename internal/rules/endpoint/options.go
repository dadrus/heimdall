package endpoint

type Option func(*Endpoint)

func WithMethod(method string) Option {
	return func(ep *Endpoint) {
		ep.Method = method
	}
}

func WithHeader(name, value string) Option {
	return func(ep *Endpoint) {
		ep.SetHeader(name, value)
	}
}

func WithAuthStrategy(strategy AuthenticationStrategy) Option {
	return func(ep *Endpoint) {
		ep.AuthStrategy = strategy
	}
}

func WithRetry(retry *Retry) Option {
	return func(ep *Endpoint) {
		ep.Retry = retry
	}
}

func WithHTTPCache(cch *HTTPCache) Option {
	return func(ep *Endpoint) {
		ep.HTTPCache = cch
	}
}

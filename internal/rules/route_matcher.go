package rules

import (
	"errors"
	"github.com/dadrus/heimdall/internal/rules/config"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/slicex"
)

// nolint: gochecknoglobals
var spaceReplacer = strings.NewReplacer("\t", "", "\n", "", "\v", "", "\f", "", "\r", "", " ", "")

var (
	ErrRequestSchemeMismatch = errors.New("request scheme mismatch")
	ErrRequestMethodMismatch = errors.New("request method mismatch")
	ErrRequestHostMismatch   = errors.New("request host mismatch")
	ErrRequestPathMismatch   = errors.New("request path mismatch")
)

//go:generate mockery --name RouteMatcher --structname RouteMatcherMock

type RouteMatcher interface {
	Matches(request *heimdall.Request, keys, values []string) error
}

type compositeMatcher []RouteMatcher

func (c compositeMatcher) Matches(request *heimdall.Request, keys, values []string) error {
	for _, matcher := range c {
		if err := matcher.Matches(request, keys, values); err != nil {
			return err
		}
	}

	return nil
}

type alwaysMatcher struct{}

func (alwaysMatcher) match(_ string) bool { return true }

type schemeMatcher string

func (s schemeMatcher) Matches(request *heimdall.Request, _, _ []string) error {
	if len(s) != 0 && string(s) != request.URL.Scheme {
		return errorchain.NewWithMessagef(ErrRequestSchemeMismatch, "expected %s, got %s", s, request.URL.Scheme)
	}

	return nil
}

type methodMatcher []string

func (m methodMatcher) Matches(request *heimdall.Request, _, _ []string) error {
	if len(m) == 0 {
		return nil
	}

	if !slices.Contains(m, request.Method) {
		return errorchain.NewWithMessagef(ErrRequestMethodMismatch, "%s is not expected", request.Method)
	}

	return nil
}

type hostMatcher struct {
	typedMatcher
}

func (m *hostMatcher) Matches(request *heimdall.Request, _, _ []string) error {
	if !m.match(request.URL.Host) {
		return errorchain.NewWithMessagef(ErrRequestHostMismatch, "%s is not expected", request.URL.Host)
	}

	return nil
}

type paramMatcher struct {
	typedMatcher

	name string
}

func (m *paramMatcher) Matches(_ *heimdall.Request, keys, values []string) error {
	idx := slices.Index(keys, m.name)
	if idx == -1 {
		return errorchain.NewWithMessagef(ErrRequestPathMismatch, "%s is not expected", m.name)
	}

	value := values[idx]
	if !m.match(value) {
		return errorchain.NewWithMessagef(ErrRequestPathMismatch, "%s is not expected", value)
	}

	return nil
}

type pathMatcher struct {
	typedMatcher

	slashHandling config.EncodedSlashesHandling
}

func (m *pathMatcher) Matches(request *heimdall.Request) error {
	var path string
	if len(request.URL.RawPath) == 0 || m.slashHandling == config.EncodedSlashesOn {
		path = request.URL.Path
	} else {
		unescaped, _ := url.PathUnescape(strings.ReplaceAll(request.URL.RawPath, "%2F", "$$$escaped-slash$$$"))
		path = strings.ReplaceAll(unescaped, "$$$escaped-slash$$$", "%2F")
	}

	if !m.match(path) {
		return errorchain.NewWithMessagef(ErrRequestPathMismatch, "%s is not expected", path)
	}

	return nil
}

func createMethodMatcher(methods []string) (methodMatcher, error) {
	if len(methods) == 0 {
		return methodMatcher{}, nil
	}

	if slices.Contains(methods, "ALL") {
		methods = slices.DeleteFunc(methods, func(method string) bool { return method == "ALL" })

		methods = append(methods,
			http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
			http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace)
	}

	slices.SortFunc(methods, strings.Compare)

	methods = slices.Compact(methods)
	if res := slicex.Filter(methods, func(s string) bool { return len(s) == 0 }); len(res) != 0 {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"methods list contains empty values. have you forgotten to put the corresponding value into braces?")
	}

	tbr := slicex.Filter(methods, func(s string) bool { return strings.HasPrefix(s, "!") })
	methods = slicex.Subtract(methods, tbr)
	tbr = slicex.Map[string, string](tbr, func(s string) string { return strings.TrimPrefix(s, "!") })

	return slicex.Subtract(methods, tbr), nil
}

func createHostMatcher(hosts []config.HostMatcher) (RouteMatcher, error) {
	matchers := make(compositeMatcher, len(hosts))

	for idx, host := range hosts {
		var (
			tm  typedMatcher
			err error
		)

		switch host.Type {
		case "glob":
			tm, err = newGlobMatcher(host.Value, '.')
		case "regex":
			tm, err = newRegexMatcher(host.Value)
		case "exact":
			matchers[idx] = &hostMatcher{&valueMatcher{host.Value}}
		default:
			return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"unsupported expression type for host")
		}

		if err != nil {
			return nil, err
		}

		matchers[idx] = &hostMatcher{tm}
	}

	return matchers, nil
}

func createParamsMatcher(params []config.ParameterMatcher) (RouteMatcher, error) {
	matchers := make(compositeMatcher, len(params))

	for idx, param := range params {
		var (
			tm  typedMatcher
			err error
		)

		switch param.Type {
		case "glob":
			tm, err = newGlobMatcher(param.Value, '/')
		case "regex":
			tm, err = newRegexMatcher(param.Value)
		case "exact":
			matchers[idx] = &paramMatcher{&valueMatcher{param.Value}, param.Name}
		default:
			return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
				"unsupported expression type for parameter")
		}

		if err != nil {
			return nil, err
		}

		matchers[idx] = &paramMatcher{tm, param.Name}
	}

	return matchers, nil
}

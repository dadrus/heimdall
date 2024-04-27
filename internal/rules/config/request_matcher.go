package config

import (
	"errors"
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

//go:generate mockery --name RequestMatcher --structname RequestMatcherMock

type RequestMatcher interface {
	Matches(request *heimdall.Request) error
}

type compositeMatcher []RequestMatcher

func (c compositeMatcher) Matches(request *heimdall.Request) error {
	for _, matcher := range c {
		if err := matcher.Matches(request); err != nil {
			return err
		}
	}

	return nil
}

type alwaysMatcher struct{}

func (alwaysMatcher) match(_ string) bool { return true }

type schemeMatcher string

func (s schemeMatcher) Matches(request *heimdall.Request) error {
	if len(s) != 0 && string(s) != request.URL.Scheme {
		return errorchain.NewWithMessagef(ErrRequestSchemeMismatch, "expected %s, got %s", s, request.URL.Scheme)
	}

	return nil
}

type methodMatcher []string

func (m methodMatcher) Matches(request *heimdall.Request) error {
	if len(m) == 0 {
		return nil
	}

	if !slices.Contains(m, request.Method) {
		return errorchain.NewWithMessagef(ErrRequestMethodMismatch, "%s is not expected", request.Method)
	}

	return nil
}

type hostMatcher struct {
	patternMatcher
}

func (m *hostMatcher) Matches(request *heimdall.Request) error {
	if !m.match(request.URL.Host) {
		return errorchain.NewWithMessagef(ErrRequestHostMismatch, "%s is not expected", request.URL.Host)
	}

	return nil
}

type pathMatcher struct {
	patternMatcher

	slashHandling EncodedSlashesHandling
}

func (m *pathMatcher) Matches(request *heimdall.Request) error {
	var path string
	if len(request.URL.RawPath) == 0 || m.slashHandling == EncodedSlashesOn {
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

func createPathMatcher(
	globExpression string, regexExpression string, slashHandling EncodedSlashesHandling,
) (*pathMatcher, error) {
	matcher, err := createPatternMatcher(globExpression, '/', regexExpression)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"filed to compile path expression").CausedBy(err)
	}

	return &pathMatcher{matcher, slashHandling}, nil
}

func createHostMatcher(globExpression string, regexExpression string) (*hostMatcher, error) {
	matcher, err := createPatternMatcher(globExpression, '.', regexExpression)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"filed to compile host expression").CausedBy(err)
	}

	return &hostMatcher{matcher}, nil
}

func createPatternMatcher(globExpression string, globSeparator rune, regexExpression string) (patternMatcher, error) {
	glob := spaceReplacer.Replace(globExpression)
	regex := spaceReplacer.Replace(regexExpression)

	switch {
	case len(glob) != 0:
		return newGlobMatcher(glob, globSeparator)
	case len(regex) != 0:
		return newRegexMatcher(regex)
	default:
		return alwaysMatcher{}, nil
	}
}

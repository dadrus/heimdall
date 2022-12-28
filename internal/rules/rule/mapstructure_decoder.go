package rule

import (
	"errors"
	"reflect"

	"github.com/dadrus/heimdall/internal/x"
)

var ErrURLMissing = errors.New("missing matching URL")

func decodeRuleMatcher(from reflect.Type, to reflect.Type, data any) (any, error) {
	if to != reflect.TypeOf(Matcher{}) {
		return data, nil
	}

	if from.Kind() == reflect.String {
		// nolint: forcetypeassert
		// already checked above
		return Matcher{URL: data.(string), Strategy: "glob"}, nil
	} else if from.Kind() == reflect.Map {
		// nolint: forcetypeassert
		// already checked above
		values := data.(map[string]any)

		URL, urlPresent := values["url"]
		strategy, strategyPresent := values["strategy"]

		if !urlPresent {
			return nil, ErrURLMissing
		}

		// nolint: forcetypeassert
		// already checked above
		return Matcher{
			URL: URL.(string),
			Strategy: x.IfThenElseExec(strategyPresent,
				func() string { return strategy.(string) },
				func() string { return "glob" }),
		}, nil
	}

	return data, nil
}

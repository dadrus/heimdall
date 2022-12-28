package rule

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/dadrus/heimdall/internal/x"
)

var (
	ErrURLMissing          = errors.New("url property not present")
	ErrURLType             = errors.New("bad url type")
	ErrStrategyType        = errors.New("bad strategy type")
	ErrUnsupportedStrategy = errors.New("unsupported strategy")
)

func decodeMatcher(from reflect.Type, to reflect.Type, data any) (any, error) {
	if to != reflect.TypeOf(Matcher{}) {
		return data, nil
	}

	if from.Kind() != reflect.String && from.Kind() != reflect.Map {
		return data, nil
	}

	if from.Kind() == reflect.String {
		// nolint: forcetypeassert
		// already checked above
		return Matcher{URL: data.(string), Strategy: "glob"}, nil
	}

	// nolint: forcetypeassert
	// already checked above
	values := data.(map[string]any)

	var strategyValue string

	URL, urlPresent := values["url"]
	if !urlPresent {
		return nil, ErrURLMissing
	}

	urlValue, ok := URL.(string)
	if !ok {
		return nil, ErrURLType
	}

	strategy, strategyPresent := values["strategy"]
	if strategyPresent {
		strategyValue, ok = strategy.(string)
		if !ok {
			return nil, ErrStrategyType
		}

		if strategyValue != "glob" && strategyValue != "regex" {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedStrategy, strategyValue)
		}
	}

	return Matcher{
		URL:      urlValue,
		Strategy: x.IfThenElse(strategyPresent, strategyValue, "glob"),
	}, nil
}

package template

import (
	"fmt"
	"net/url"
	"reflect"

	"github.com/dadrus/heimdall/internal/secrets"
)

func urlEncode(value any) string {
	switch t := value.(type) {
	case string:
		return url.QueryEscape(t)
	case fmt.Stringer:
		return url.QueryEscape(t.String())
	default:
		return ""
	}
}

func atIndex(pos int, list any) (any, error) {
	tp := reflect.TypeOf(list).Kind()
	switch tp {
	case reflect.Slice, reflect.Array:
		l2 := reflect.ValueOf(list)

		length := l2.Len()
		if length == 0 {
			return nil, nil // nolint: nilnil
		}

		if pos >= 0 && pos >= length {
			// nolint: err113
			return nil, fmt.Errorf("cannot at(%d), position is outside of the list boundaries", pos)
		}

		if pos < 0 && (-pos-1) >= length {
			// nolint: err113
			return nil, fmt.Errorf("cannot at(%d), position is outside of the list boundaries", pos)
		}

		if pos >= 0 {
			return l2.Index(pos).Interface(), nil
		}

		return l2.Index(length + pos).Interface(), nil

	default:
		// nolint: err113
		return nil, fmt.Errorf("cannot find at on type %s", tp)
	}
}

func secret(store secrets.Store) func(string, string) (string, error) {
	return func(source, selector string) (string, error) {
		return store.GetSecret(secrets.Reference{
			Source:   source,
			Selector: selector,
		})
	}
}

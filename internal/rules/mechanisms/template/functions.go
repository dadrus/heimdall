package template

import (
	"context"
	"fmt"
	"net/url"
	"reflect"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/secrets"
	"github.com/dadrus/heimdall/internal/x/errorchain"
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
			return nil, nil //nolint:nilnil
		}

		if pos >= 0 && pos >= length {
			//nolint:err113
			return nil, fmt.Errorf("cannot at(%d), position is outside of the list boundaries", pos)
		}

		if pos < 0 && (-pos-1) >= length {
			//nolint:err113
			return nil, fmt.Errorf("cannot at(%d), position is outside of the list boundaries", pos)
		}

		if pos >= 0 {
			return l2.Index(pos).Interface(), nil
		}

		return l2.Index(length + pos).Interface(), nil

	default:
		//nolint:err113
		return nil, fmt.Errorf("cannot find at on type %s", tp)
	}
}

func secret(
	informers map[secrets.Reference]*secrets.SecretInformer[string],
) func(string, string) (string, error) {
	return func(source, selector string) (string, error) {
		informer := informers[secrets.Reference{
			Source:   source,
			Selector: selector,
		}]
		if informer == nil {
			return "", errorchain.NewWithMessagef(
				pipeline.ErrConfiguration,
				"secret reference '%s/%s' is not registered",
				source,
				selector,
			)
		}

		value, ok := informer.Get(context.Background())
		if !ok {
			return "", errorchain.NewWithMessagef(
				pipeline.ErrConfiguration,
				"secret reference '%s/%s' is not available",
				source,
				selector,
			)
		}

		return value, nil
	}
}

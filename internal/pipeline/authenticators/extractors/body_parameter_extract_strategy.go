package extractors

import (
	"net/http"
	"strings"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/pipeline/contenttype"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type BodyParameterExtractStrategy struct {
	Name string
}

func (es BodyParameterExtractStrategy) GetAuthData(ctx heimdall.Context) (AuthData, error) {
	decoder, err := contenttype.NewDecoder(ctx.RequestHeader("Content-Type"))
	if err != nil {
		return nil, errorchain.New(heimdall.ErrArgument).CausedBy(err)
	}

	data, err := decoder.Decode(ctx.RequestBody())
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrArgument,
			"failed to decode request body").CausedBy(err)
	}

	entry, ok := data[es.Name]
	if !ok {
		return nil, errorchain.NewWithMessagef(heimdall.ErrArgument,
			"no %s parameter present in request body", es.Name)
	}

	var value string

	switch val := entry.(type) {
	case string:
		value = val
	case []string:
		if len(val) != 1 {
			return nil, errorchain.NewWithMessagef(heimdall.ErrArgument,
				"%s request body parameter is present multiple times", es.Name)
		}

		value = val[0]
	case []any:
		if len(val) != 1 {
			return nil, errorchain.NewWithMessagef(heimdall.ErrArgument,
				"%s request body parameter is present multiple times", es.Name)
		}

		value, ok = val[0].(string)
		if !ok {
			return nil, errorchain.NewWithMessagef(heimdall.ErrArgument,
				"unexpected type for %s request body parameter", es.Name)
		}
	default:
		return nil, errorchain.NewWithMessagef(heimdall.ErrArgument,
			"unexpected type for %s request body parameter", es.Name)
	}

	return &bodyParameterAuthData{
		name:  es.Name,
		value: strings.TrimSpace(value),
	}, nil
}

type bodyParameterAuthData struct {
	name  string
	value string
}

func (c *bodyParameterAuthData) ApplyTo(req *http.Request) {
	panic("application of extracted body parameters to a request is not yet supported")
}

func (c *bodyParameterAuthData) Value() string {
	return c.value
}

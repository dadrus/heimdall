package rulesetparser

import (
	"errors"
	"io"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func ParseRules(contentType string, reader io.Reader) ([]rule.Configuration, error) {
	switch contentType {
	case "application/json":
		fallthrough
	case "application/yaml":
		return parseYAML(reader)
	default:
		// check if the contents are empty. in that case nothing needs to be decoded anyway
		b := make([]byte, 1)
		if _, err := reader.Read(b); err != nil && errors.Is(err, io.EOF) {
			return []rule.Configuration{}, nil
		}

		// otherwise
		return nil, errorchain.NewWithMessagef(heimdall.ErrInternal,
			"unsupported '%s' content type", contentType)
	}
}

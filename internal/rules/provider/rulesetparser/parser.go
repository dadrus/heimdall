package rulesetparser

import (
	"errors"
	"io"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func ParseRules(contentType string, reader io.Reader) ([]config.RuleConfig, error) {
	switch contentType {
	case "application/yaml":
		return parseYAML(reader)
	case "application/json":
		return parseJSON(reader)
	default:
		// check if the contents are empty. in that case nothing needs to be decoded anyway
		b := make([]byte, 1)
		if _, err := reader.Read(b); err != nil && errors.Is(err, io.EOF) {
			return []config.RuleConfig{}, nil
		}

		// otherwise
		return nil, errorchain.NewWithMessagef(heimdall.ErrInternal,
			"unsupported '%s' content type", contentType)
	}
}

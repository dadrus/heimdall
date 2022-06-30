package parser

import (
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func koanfFromEnv() (*koanf.Koanf, error) {
	parser := koanf.New(".")

	err := parser.Load(env.Provider("", ".", strings.ToLower), nil)
	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to parse environment variables to config").CausedBy(err)
	}

	return transformEnvFormat(parser)
}

func transformEnvFormat(parser *koanf.Koanf) (*koanf.Koanf, error) {
	exploded := make(map[string]any)

	for key, value := range parser.All() {
		keys := expandSlices(strings.Split(key, "_"))
		for _, newKey := range keys {
			exploded[strings.ToLower(newKey)] = value
		}
	}

	parser = koanf.New(".")

	err := parser.Load(confmap.Provider(exploded, "."), nil)
	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to parse flattened environment variables to config").CausedBy(err)
	}

	return parser, nil
}

func expandSlices(parts []string) []string {
	if len(parts) == 1 {
		return parts
	}

	next := expandSlices(parts[1:])
	// nolint
	result := make([]string, 0, len(next)*2)

	for _, k := range next {
		result = append(result, parts[0]+"."+k)
		result = append(result, parts[0]+"_"+k)
	}

	return result
}

package parser

import (
	"os"

	"github.com/drone/envsubst/v2"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

func koanfFromYaml(configFile string) (*koanf.Koanf, error) {
	parser := koanf.New(".")

	raw, err := os.ReadFile(configFile)
	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to read yaml config from %s", configFile).CausedBy(err)
	}

	content, err := envsubst.EvalEnv(string(raw))
	if err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to parse yaml config from %s", configFile).CausedBy(err)
	}

	if err = parser.Load(rawbytes.Provider([]byte(content)), yaml.Parser()); err != nil {
		return nil, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"failed to load yaml config from %s", configFile).CausedBy(err)
	}

	return parser, nil
}

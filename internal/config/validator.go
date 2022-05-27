package config

import (
	"os"

	"github.com/knadh/koanf/maps"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/schema"
)

func ValidateConfig(configPath string) error {
	contents, err := os.ReadFile(configPath)
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"could not read config file").CausedBy(err)
	}

	var conf map[string]any

	err = yaml.Unmarshal(contents, &conf)
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed to parse config file").CausedBy(err)
	}

	schema, err := jsonschema.CompileString("config.schema.json", string(schema.ConfigSchema))
	if err != nil {
		return errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed to compile JSON schema").CausedBy(err)
	}

	maps.IntfaceKeysToStrings(conf)

	err = schema.Validate(conf)
	if err != nil {
		return errorchain.New(heimdall.ErrConfiguration).CausedBy(err)
	}

	return nil
}

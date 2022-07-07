package parser

import (
	"fmt"
	"os"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/mitchellh/mapstructure"
)

type ConfigLoader interface {
	Load(config any) error
}

func New(opts ...Option) ConfigLoader {
	loader := &configLoader{o: defaultOptions}

	for _, opt := range opts {
		opt(&loader.o)
	}

	return loader
}

type configLoader struct {
	o opts
}

func (c *configLoader) Load(config any) error {
	configFile, err := c.configFile()
	if err != nil {
		return err
	}

	if len(configFile) != 0 && c.o.validate != nil {
		if err := c.o.validate(configFile); err != nil {
			return err
		}
	}

	parser, err := koanfFromStruct(config)
	if err != nil {
		return err
	}

	parser.Print()

	loadAndMergeConfig := func(loadConfig func() (*koanf.Koanf, error)) error {
		konf, err := loadConfig()
		if err != nil {
			return err
		}

		return parser.Load(
			confmap.Provider(konf.Raw(), ""),
			nil,
			koanf.WithMergeFunc(func(src, dest map[string]any) error {
				for key, val := range src {
					dest[key] = merge(dest[key], val)
				}

				return nil
			}))
	}

	if len(configFile) != 0 {
		if err := loadAndMergeConfig(func() (*koanf.Koanf, error) {
			return koanfFromYaml(configFile)
		}); err != nil {
			return err
		}
	}

	if err := loadAndMergeConfig(func() (*koanf.Koanf, error) {
		return koanfFromEnv(c.o.envPrefix)
	}); err != nil {
		return err
	}

	return parser.UnmarshalWithConf("", config, koanf.UnmarshalConf{
		Tag: "koanf",
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook:       mapstructure.ComposeDecodeHookFunc(c.o.decodeHooks...),
			Metadata:         nil,
			Result:           config,
			WeaklyTypedInput: true,
		},
	})
}

func (c *configLoader) configFile() (string, error) {
	if len(c.o.configFile) != 0 {
		_, err := os.Stat(c.o.configFile)
		if err != nil {
			return "", err
		}

		return c.o.configFile, nil
	}

	for _, confDir := range c.o.configLookupDirs {
		filePath := fmt.Sprintf("%s/%s", confDir, c.o.defaultConfigFileName)
		if _, err := os.Stat(filePath); err == nil {
			return filePath, nil
		}
	}

	return "", nil
}

package parser

import (
	"strings"

	"github.com/mitchellh/mapstructure"
)

type ConfigValidator func(configPath string) error

type opts struct {
	configFile            string
	defaultConfigFileName string
	configLookupDirs      []string
	decodeHooks           []mapstructure.DecodeHookFunc
	validate              ConfigValidator
}

type Option func(*opts)

func WithConfigFile(file string) Option {
	return func(o *opts) {
		configFile := strings.TrimSpace(file)
		if len(configFile) != 0 {
			o.configFile = configFile
		}
	}
}

func WithDefaultConfigFilename(name string) Option {
	return func(o *opts) {
		fileName := strings.TrimSpace(name)
		if len(fileName) != 0 {
			o.defaultConfigFileName = fileName
		}
	}
}

func WithDecodeHookFunc(hook mapstructure.DecodeHookFunc) Option {
	return func(o *opts) {
		if hook != nil {
			o.decodeHooks = append(o.decodeHooks, hook)
		}
	}
}

func WithConfigLookupDir(file string) Option {
	return func(o *opts) {
		dir := strings.TrimSpace(file)
		if len(dir) != 0 {
			o.configLookupDirs = append(o.configLookupDirs, dir)
		}
	}
}

func WithConfigValidator(validator ConfigValidator) Option {
	return func(o *opts) {
		if validator != nil {
			o.validate = validator
		}
	}
}

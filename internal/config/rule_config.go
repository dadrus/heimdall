package config

import "github.com/goccy/go-json"

type PipelineConfig map[string]any

func (in *PipelineConfig) DeepCopyInto(out *PipelineConfig) {
	if in == nil {
		return
	}

	jsonStr, _ := json.Marshal(in)

	// we cannot do anything with an error here as
	// the interface implemented here doesn't support
	// error responses
	json.Unmarshal(jsonStr, out) //nolint:errcheck
}

type DefaultRuleConfig struct {
	Methods      []string         `koanf:"methods"`
	Execute      []PipelineConfig `koanf:"execute"`
	ErrorHandler []PipelineConfig `koanf:"on_error"`
}

type RuleConfig struct {
	ID               string           `yaml:"id"`
	URL              string           `yaml:"url"`
	Upstream         string           `yaml:"upstream"`
	MatchingStrategy string           `yaml:"matching_strategy"`
	Methods          []string         `yaml:"methods"`
	Execute          []PipelineConfig `yaml:"execute"`
	ErrorHandler     []PipelineConfig `yaml:"on_error"`
}

func (in *RuleConfig) DeepCopyInto(out *RuleConfig) {
	*out = *in
	if in.Methods != nil {
		in, out := &in.Methods, &out.Methods

		*out = make([]string, len(*in))
		copy(*out, *in)
	}

	if in.Execute != nil {
		in, out := &in.Execute, &out.Execute

		*out = make([]PipelineConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}

	if in.ErrorHandler != nil {
		in, out := &in.ErrorHandler, &out.ErrorHandler

		*out = make([]PipelineConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

func (in *RuleConfig) DeepCopy() *RuleConfig {
	if in == nil {
		return nil
	}

	out := new(RuleConfig)
	in.DeepCopyInto(out)

	return out
}

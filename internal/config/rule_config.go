package config

type DefaultRuleConfig struct {
	Methods      []string          `koanf:"methods"`
	Execute      []MechanismConfig `koanf:"execute"`
	ErrorHandler []MechanismConfig `koanf:"on_error"`
}

type RuleConfig struct {
	ID               string            `json:"id" yaml:"id"`
	URL              string            `json:"url" yaml:"url"`
	Upstream         string            `json:"upstream" yaml:"upstream"`
	MatchingStrategy string            `json:"matching_strategy" yaml:"matching_strategy"`
	Methods          []string          `json:"methods" yaml:"methods"`
	Execute          []MechanismConfig `json:"execute" yaml:"execute"`
	ErrorHandler     []MechanismConfig `json:"on_error" yaml:"on_error"`
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

		*out = make([]MechanismConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}

	if in.ErrorHandler != nil {
		in, out := &in.ErrorHandler, &out.ErrorHandler

		*out = make([]MechanismConfig, len(*in))
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

package rule

import "github.com/dadrus/heimdall/internal/config"

type Configuration struct {
	ID           string                   `json:"id" yaml:"id"`
	RuleMatcher  Matcher                  `json:"match" yaml:"match"`
	Upstream     string                   `json:"upstream" yaml:"upstream"`
	Methods      []string                 `json:"methods" yaml:"methods"`
	Execute      []config.MechanismConfig `json:"execute" yaml:"execute"`
	ErrorHandler []config.MechanismConfig `json:"on_error" yaml:"on_error"`
}

func (in *Configuration) DeepCopyInto(out *Configuration) {
	*out = *in
	out.RuleMatcher = in.RuleMatcher

	if in.Methods != nil {
		in, out := &in.Methods, &out.Methods

		*out = make([]string, len(*in))
		copy(*out, *in)
	}

	if in.Execute != nil {
		in, out := &in.Execute, &out.Execute

		*out = make([]config.MechanismConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}

	if in.ErrorHandler != nil {
		in, out := &in.ErrorHandler, &out.ErrorHandler

		*out = make([]config.MechanismConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

func (in *Configuration) DeepCopy() *Configuration {
	if in == nil {
		return nil
	}

	out := new(Configuration)
	in.DeepCopyInto(out)

	return out
}

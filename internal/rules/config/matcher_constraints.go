package config

import "slices"

type MatcherConstraints struct {
	Scheme    string   `json:"scheme"     yaml:"scheme"     validate:"omitempty,oneof=http https"` //nolint:tagalign
	Methods   []string `json:"methods"    yaml:"methods"    validate:"omitempty,dive,required"`    //nolint:tagalign
	HostGlob  string   `json:"host_glob"  yaml:"host_glob"  validate:"excluded_with=HostRegex"`    //nolint:tagalign
	HostRegex string   `json:"host_regex" yaml:"host_regex" validate:"excluded_with=HostGlob"`     //nolint:tagalign
	PathGlob  string   `json:"path_glob"  yaml:"path_glob"  validate:"excluded_with=PathRegex"`    //nolint:tagalign
	PathRegex string   `json:"path_regex" yaml:"path_regex" validate:"excluded_with=PathGlob"`     //nolint:tagalign
}

func (mc *MatcherConstraints) ToRequestMatcher(slashHandling EncodedSlashesHandling) (RequestMatcher, error) {
	if mc == nil {
		return compositeMatcher{}, nil
	}

	hostMatcher, err := createHostMatcher(mc.HostGlob, mc.HostRegex)
	if err != nil {
		return nil, err
	}

	pathMatcher, err := createPathMatcher(mc.PathGlob, mc.PathRegex, slashHandling)
	if err != nil {
		return nil, err
	}

	methodMatcher, err := createMethodMatcher(mc.Methods)
	if err != nil {
		return nil, err
	}

	return compositeMatcher{
		schemeMatcher(mc.Scheme),
		methodMatcher,
		hostMatcher,
		pathMatcher,
	}, nil
}

func (mc *MatcherConstraints) DeepCopyInto(out *MatcherConstraints) {
	*out = *mc

	out.Methods = slices.Clone(mc.Methods)
}

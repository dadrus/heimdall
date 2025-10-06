package converter

import (
	"bytes"
	"errors"

	"github.com/goccy/go-json"

	"github.com/dadrus/heimdall/internal/rules/api/v1alpha4"
	"github.com/dadrus/heimdall/internal/rules/api/v1beta1"
	"github.com/dadrus/heimdall/internal/rules/encoding"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrConversion = errors.New("conversion error")

type (
	Converter interface {
		Convert(data []byte, format string) ([]byte, error)
	}

	unstructuredRuleSet map[string]any

	converter struct {
		toVersion string
	}
)

func New(targetVersion string) Converter {
	return &converter{
		toVersion: targetVersion,
	}
}

// nolint: cyclop
func (c *converter) Convert(rawObj []byte, format string) ([]byte, error) {
	var (
		urs       unstructuredRuleSet
		err       error
		converted any
	)

	dec := encoding.NewDecoder(encoding.WithSourceContentType(format))
	enc := encoding.NewEncoder(encoding.WithTargetContentType(format))

	if err = dec.Decode(&urs, bytes.NewBuffer(rawObj)); err != nil {
		return nil, errorchain.NewWithMessage(ErrConversion,
			"failed to unmarshal rule set").CausedBy(err)
	}

	fromVersion := urs.Version()
	if fromVersion == c.toVersion {
		return nil, errorchain.NewWithMessagef(ErrConversion,
			"rule set is already in the expected version: %s", c.toVersion)
	}

	switch fromVersion {
	case v1alpha4.Version:
		if c.toVersion != v1beta1.Version {
			return nil, errorchain.NewWithMessagef(ErrConversion,
				"unexpected target rule set version: %s", c.toVersion)
		}

		var sourceRs v1alpha4.RuleSet
		if err = dec.Decode(&sourceRs, bytes.NewReader(rawObj)); err != nil {
			return nil, err
		}

		converted, err = c.convertV1Alpha4ToV1Beta1(&sourceRs)
		if err != nil {
			return nil, err
		}
	case v1beta1.Version:
		if c.toVersion != v1alpha4.Version {
			return nil, errorchain.NewWithMessagef(
				ErrConversion, "unexpected target rule set version: %s", c.toVersion)
		}

		var sourceRs v1beta1.RuleSet
		if err = dec.Decode(&sourceRs, bytes.NewReader(rawObj)); err != nil {
			return nil, err
		}

		converted, err = c.convertV1Beta1ToV1Alpha4(&sourceRs)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errorchain.NewWithMessagef(
			ErrConversion, "unexpected source rule set version: %s", fromVersion)
	}

	buf := &bytes.Buffer{}
	if err = enc.Encode(converted, buf); err != nil {
		return nil, errorchain.NewWithMessage(ErrConversion, "failed to marshal converted rule set").
			CausedBy(err)
	}

	return buf.Bytes(), nil
}

func (c *converter) convertV1Beta1ToV1Alpha4(sourceRs *v1beta1.RuleSet) (*v1alpha4.RuleSet, error) {
	convertedRules := make([]v1alpha4.Rule, len(sourceRs.Rules))

	for idx, rul := range sourceRs.Rules {
		routes, err := convertObject[[]v1beta1.Route, []v1alpha4.Route](rul.Matcher.Routes)
		if err != nil {
			return nil, errorchain.NewWithMessagef(ErrConversion,
				"failed converting matcher routes for rule %s", rul.ID).CausedBy(err)
		}

		backend, err := convertObject[v1beta1.Backend, v1alpha4.Backend](*rul.Backend)
		if err != nil {
			return nil, errorchain.NewWithMessagef(ErrConversion,
				"failed converting forward_to for rule %s", rul.ID).CausedBy(err)
		}

		hosts := make([]v1alpha4.HostMatcher, len(rul.Matcher.Hosts))
		for idx, host := range rul.Matcher.Hosts {
			hosts[idx] = v1alpha4.HostMatcher{Value: host, Type: "wildcard"}
		}

		convertedRules[idx] = v1alpha4.Rule{
			ID:                     rul.ID,
			EncodedSlashesHandling: v1alpha4.EncodedSlashesHandling(rul.EncodedSlashesHandling),
			Matcher: v1alpha4.Matcher{
				Routes:  routes,
				Scheme:  rul.Matcher.Scheme,
				Methods: rul.Matcher.Methods,
				Hosts:   hosts,
			},
			Backend:      &backend,
			Execute:      rul.Execute,
			ErrorHandler: rul.ErrorHandler,
		}
	}

	return &v1alpha4.RuleSet{
		Version: c.toVersion,
		Name:    sourceRs.Name,
		Rules:   convertedRules,
	}, nil
}

func (c *converter) convertV1Alpha4ToV1Beta1(sourceRs *v1alpha4.RuleSet) (*v1beta1.RuleSet, error) {
	convertedRules := make([]v1beta1.Rule, len(sourceRs.Rules))

	for idx, rul := range sourceRs.Rules {
		routes, err := convertObject[[]v1alpha4.Route, []v1beta1.Route](rul.Matcher.Routes)
		if err != nil {
			return nil, errorchain.NewWithMessagef(ErrConversion,
				"failed converting matcher routes for rule %s", rul.ID).CausedBy(err)
		}

		backend, err := convertObject[v1alpha4.Backend, v1beta1.Backend](*rul.Backend)
		if err != nil {
			return nil, errorchain.NewWithMessagef(ErrConversion,
				"failed converting forward_to for rule %s", rul.ID).CausedBy(err)
		}

		hosts := make([]string, len(rul.Matcher.Hosts))
		for idx, host := range rul.Matcher.Hosts {
			hosts[idx] = host.Value
		}

		convertedRules[idx] = v1beta1.Rule{
			ID:                     rul.ID,
			EncodedSlashesHandling: v1beta1.EncodedSlashesHandling(rul.EncodedSlashesHandling),
			Matcher: v1beta1.Matcher{
				Routes:  routes,
				Scheme:  rul.Matcher.Scheme,
				Methods: rul.Matcher.Methods,
				Hosts:   hosts,
			},
			Backend:      &backend,
			Execute:      rul.Execute,
			ErrorHandler: rul.ErrorHandler,
		}
	}

	return &v1beta1.RuleSet{
		Version: c.toVersion,
		Name:    sourceRs.Name,
		Rules:   convertedRules,
	}, nil
}

func (rs unstructuredRuleSet) Version() string { return rs.getStringValue("version") }

func (rs unstructuredRuleSet) getStringValue(key string) string {
	val, ok := rs[key]
	if !ok {
		return ""
	}

	stringVal, ok := val.(string)
	if !ok {
		return ""
	}

	return stringVal
}

func convertObject[From any, To any](from From) (To, error) {
	var to To

	raw, err := json.Marshal(from)
	if err != nil {
		return to, err
	}

	if err := json.Unmarshal(raw, &to); err != nil {
		return to, err
	}

	return to, nil
}

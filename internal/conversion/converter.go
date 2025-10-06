package conversion

import (
	"bytes"
	"errors"

	"github.com/goccy/go-json"

	"github.com/dadrus/heimdall/internal/rules/api/common"
	"github.com/dadrus/heimdall/internal/rules/api/v1alpha4"
	"github.com/dadrus/heimdall/internal/rules/api/v1beta1"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrConversion = errors.New("conversion error")

type (
	Converter interface {
		ConvertRuleSet(data []byte, format string) ([]byte, error)
	}

	unstructuredRuleSet map[string]any

	ruleSetConverter struct {
		toVersion string
	}
)

func NewRuleSetConverter(targetVersion string) Converter {
	return &ruleSetConverter{
		toVersion: targetVersion,
	}
}

// nolint: gocognit
func (c *ruleSetConverter) ConvertRuleSet(rawObj []byte, format string) ([]byte, error) {
	var urs unstructuredRuleSet

	dec := common.NewDecoder(common.WithSourceContentType(format))
	enc := common.NewEncoder(common.WithTargetContentType(format))

	if err := dec.Decode(&urs, bytes.NewBuffer(rawObj)); err != nil {
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
		if err := dec.Decode(&sourceRs, bytes.NewReader(rawObj)); err != nil {
			return nil, err
		}

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

		convertedRs := v1beta1.RuleSet{
			Version: c.toVersion,
			Name:    sourceRs.Name,
			Rules:   convertedRules,
		}

		buf := &bytes.Buffer{}
		if err := enc.Encode(&convertedRs, buf); err != nil {
			return nil, errorchain.NewWithMessage(ErrConversion, "failed to marshal converted rule set").
				CausedBy(err)
		}

		return buf.Bytes(), nil
	case v1beta1.Version:
		if c.toVersion != v1alpha4.Version {
			return nil, errorchain.NewWithMessagef(
				ErrConversion, "unexpected target rule set version: %s", c.toVersion)
		}

		var sourceRs v1beta1.RuleSet
		if err := dec.Decode(&sourceRs, bytes.NewReader(rawObj)); err != nil {
			return nil, err
		}

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

		convertedRs := v1alpha4.RuleSet{
			Version: c.toVersion,
			Name:    sourceRs.Name,
			Rules:   convertedRules,
		}

		buf := &bytes.Buffer{}
		if err := enc.Encode(&convertedRs, buf); err != nil {
			return nil, errorchain.NewWithMessage(ErrConversion, "failed to marshal converted rule set").
				CausedBy(err)
		}

		return buf.Bytes(), nil
	default:
		return nil, errorchain.NewWithMessagef(
			ErrConversion, "unexpected source rule set version: %s", fromVersion)
	}
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

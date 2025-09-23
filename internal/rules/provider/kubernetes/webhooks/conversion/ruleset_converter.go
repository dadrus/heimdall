package conversion

import (
	"context"
	"errors"
	"net/http"

	"github.com/goccy/go-json"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1alpha4"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1beta1"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrConversion    = errors.New("conversion error")
	ErrInvalidObject = errors.New("invalid object")
)

type rulesetConverter struct{}

func (rc *rulesetConverter) Handle(ctx context.Context, req *request) *response {
	convertedObjects := make([]runtime.RawExtension, len(req.Objects))

	if len(req.Objects) == 0 {
		return newResponse(http.StatusBadRequest, "no objects to convert provided")
	}

	for idx, obj := range req.Objects {
		cr := unstructured.Unstructured{}
		if err := cr.UnmarshalJSON(obj.Raw); err != nil {
			return newResponse(
				http.StatusInternalServerError,
				"failed to unmarshall object",
				withReasons(err.Error()),
			)
		}

		toVersion, err := schema.ParseGroupVersion(req.DesiredAPIVersion)
		if err != nil {
			return newResponse(
				http.StatusBadRequest,
				"failed to parse desired api version",
				withReasons(err.Error()),
			)
		}

		fromVersion, err := schema.ParseGroupVersion(cr.GetAPIVersion())
		if err != nil {
			return newResponse(
				http.StatusBadRequest,
				"failed to parse current object api version",
				withReasons(err.Error()),
			)
		}

		if fromVersion.Group != v1beta1.GroupVersion.Group || toVersion.Group != v1beta1.GroupVersion.Group {
			return newResponse(
				http.StatusBadRequest,
				"unexpected object groups from="+fromVersion.Group+", to=%s"+toVersion.Group,
			)
		}

		objKind := cr.GetKind()
		if objKind != v1beta1.ResourceName {
			return newResponse(
				http.StatusBadRequest,
				"expected "+v1beta1.ResourceName+" but got "+objKind,
			)
		}

		if fromVersion.Version == toVersion.Version {
			return newResponse(
				http.StatusBadRequest,
				"rule set is already in the expected version: "+toVersion.String(),
			)
		}

		converted, err := rc.convertSpec(ctx, obj.Raw, fromVersion, toVersion)
		if err != nil {
			return newResponse(
				http.StatusBadRequest,
				"failed to convert rule set",
				withReasons(err.Error()),
			)
		}

		cr.Object["spec"] = converted
		cr.SetAPIVersion(toVersion.String())
		convertedObjects[idx] = runtime.RawExtension{Object: &cr}
	}

	return newResponse(
		http.StatusOK,
		"rule sets converted",
		withConvertedObjects(convertedObjects),
	)
}

func (rc *rulesetConverter) convertSpec(
	ctx context.Context,
	rawObj []byte,
	fromVersion, toVersion schema.GroupVersion,
) (any, error) {
	switch fromVersion {
	case v1alpha4.GroupVersion:
		if toVersion != v1beta1.GroupVersion {
			return nil, errorchain.NewWithMessagef(
				ErrConversion, "unexpected conversion version %s", toVersion)
		}

		var (
			err       error
			rs        v1alpha4.RuleSet
			converted []config.Rule
		)
		if err = json.Unmarshal(rawObj, &rs); err != nil {
			return nil, err
		}

		converted = rc.convertRules(ctx, rs.Spec.Rules, toVersion)

		return v1beta1.RuleSetSpec{
			AuthClassName: rs.Spec.AuthClassName,
			Rules:         converted,
		}, nil
	case v1beta1.GroupVersion:
		if toVersion != v1alpha4.GroupVersion {
			return nil, errorchain.NewWithMessagef(
				ErrConversion, "unexpected conversion version %s", toVersion)
		}

		var (
			err       error
			rs        v1beta1.RuleSet
			converted []config.Rule
		)
		if err = json.Unmarshal(rawObj, &rs); err != nil {
			return nil, err
		}

		converted = rc.convertRules(ctx, rs.Spec.Rules, toVersion)

		return v1alpha4.RuleSetSpec{
			AuthClassName: rs.Spec.AuthClassName,
			Rules:         converted,
		}, nil
	default:
		return nil, errorchain.NewWithMessagef(
			ErrConversion, "unexpected conversion version %s", toVersion)
	}
}

func (rc *rulesetConverter) convertRules(
	_ context.Context,
	rules []config.Rule,
	_ schema.GroupVersion,
) []config.Rule {
	converted := make([]config.Rule, len(rules))

	for idx, rul := range rules {
		converted[idx] = config.Rule{
			ID:                     rul.ID,
			EncodedSlashesHandling: rul.EncodedSlashesHandling,
			Matcher: config.Matcher{
				Routes:  rul.Matcher.Routes,
				Scheme:  rul.Matcher.Scheme,
				Methods: rul.Matcher.Methods,
				Hosts:   rul.Matcher.Hosts,
			},
			Backend:      rul.Backend,
			Execute:      rul.Execute,
			ErrorHandler: rul.ErrorHandler,
		}
	}

	return converted
}

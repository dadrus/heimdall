package conversion

import (
	"context"
	"errors"
	"net/http"

	"github.com/goccy/go-json"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	cfgv1alpha4 "github.com/dadrus/heimdall/internal/rules/api/v1alpha4"
	cfgv1beta1 "github.com/dadrus/heimdall/internal/rules/api/v1beta1"
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
			err error
			rs  v1alpha4.RuleSet
		)
		if err = json.Unmarshal(rawObj, &rs); err != nil {
			return nil, err
		}

		converted := make([]cfgv1beta1.Rule, len(rs.Spec.Rules))

		for idx, rul := range rs.Spec.Rules {
			routes, err := convertObject[[]cfgv1alpha4.Route, []cfgv1beta1.Route](rul.Matcher.Routes)
			if err != nil {
				return nil, err
			}

			backend, err := convertObject[cfgv1alpha4.Backend, cfgv1beta1.Backend](*rul.Backend)
			if err != nil {
				return nil, err
			}

			hosts := make([]string, len(rul.Matcher.Hosts))
			for idx, host := range rul.Matcher.Hosts {
				hosts[idx] = host.Value
			}

			converted[idx] = cfgv1beta1.Rule{
				ID:                     rul.ID,
				EncodedSlashesHandling: rul.EncodedSlashesHandling,
				Matcher: cfgv1beta1.Matcher{
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
			err error
			rs  v1beta1.RuleSet
		)
		if err = json.Unmarshal(rawObj, &rs); err != nil {
			return nil, err
		}

		converted := make([]cfgv1alpha4.Rule, len(rs.Spec.Rules))

		for idx, rul := range rs.Spec.Rules {
			routes, err := convertObject[[]cfgv1beta1.Route, []cfgv1alpha4.Route](rul.Matcher.Routes)
			if err != nil {
				return nil, err
			}

			backend, err := convertObject[cfgv1beta1.Backend, cfgv1alpha4.Backend](*rul.Backend)
			if err != nil {
				return nil, err
			}

			hosts := make([]cfgv1alpha4.HostMatcher, len(rul.Matcher.Hosts))
			for idx, host := range rul.Matcher.Hosts {
				hosts[idx] = cfgv1alpha4.HostMatcher{Value: host, Type: "wildcard"}
			}

			converted[idx] = cfgv1alpha4.Rule{
				ID:                     rul.ID,
				EncodedSlashesHandling: rul.EncodedSlashesHandling,
				Matcher: cfgv1alpha4.Matcher{
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

		return v1alpha4.RuleSetSpec{
			AuthClassName: rs.Spec.AuthClassName,
			Rules:         converted,
		}, nil
	default:
		return nil, errorchain.NewWithMessagef(
			ErrConversion, "unexpected conversion version %s", toVersion)
	}
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

package conversion

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/goccy/go-json"
	"github.com/rs/zerolog"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1beta1"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/controller/webhook"
	"github.com/dadrus/heimdall/internal/rules/rule"
)

var ErrConversion = errors.New("conversion error")
var ErrInvalidObject = errors.New("invalid object")

type rulesetConverter struct {
}

func (rc *rulesetConverter) Handle(ctx context.Context, req *request) *response {
	_ = zerolog.Ctx(ctx)

	convertedObjects := make([]runtime.RawExtension, len(req.Objects))

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

		converted, err := rc.convert(ctx, &cr, fromVersion, toVersion)
		if err != nil {
			return newResponse(
				http.StatusBadRequest,
				"failed to convert rule set",
				withReasons(err.Error()),
			)
		}

		convertedObjects[idx] = runtime.RawExtension{Object: converted}
	}

	return newResponse(
		http.StatusOK,
		"rule sets converted",
		withConvertedObjects(convertedObjects),
	)
}

func (rc *rulesetConverter) ruleSetFrom(raw []byte) (*v1beta1.RuleSet, error) {
	rs := &v1beta1.RuleSet{}
	err := json.Unmarshal(raw, rs)

	return rs, err
}

func (rc *rulesetConverter) convert(
	ctx context.Context,
	obj *unstructured.Unstructured,
	fromVersion, toVersion schema.GroupVersion,
) (*unstructured.Unstructured, error) {
	convertedObject := obj.DeepCopy()

	switch fromVersion {
	case "v1alpha4":
		switch toVersion {
		case "v1beta1":
			hostPort, ok := convertedObject.Object["hostPort"]
			if ok {
				delete(convertedObject.Object, "hostPort")
				parts := strings.Split(hostPort.(string), ":")
				if len(parts) != 2 {
					return nil, statusErrorWithMessage("invalid hostPort value `%v`", hostPort)
				}
				convertedObject.Object["host"] = parts[0]
				convertedObject.Object["port"] = parts[1]
			}
		default:
			return nil, errorchain.NewWithMessagef(
				ErrConversion, "unexpected conversion version %s", toAPIVersion)
		}
	case v1beta1.GroupVersion:
		switch toVersion {
		case "v1alpha4":
			host, hasHost := convertedObject.Object["host"]
			port, hasPort := convertedObject.Object["port"]
			if hasHost || hasPort {
				if !hasHost {
					host = ""
				}
				if !hasPort {
					port = ""
				}
				convertedObject.Object["hostPort"] = fmt.Sprintf("%s:%s", host, port)
				delete(convertedObject.Object, "host")
				delete(convertedObject.Object, "port")
			}
		default:
			return nil, errorchain.NewWithMessagef(
				ErrConversion, "unexpected conversion version %s", toAPIVersion)
		}
	default:
		return nil, errorchain.NewWithMessagef(
			ErrConversion, "unexpected conversion version %s", toAPIVersion)
	}

	return convertedObject, nil
}

func NewHandler(factory rule.Factory, authClass string) http.Handler {
	return webhook.New(&rulesetConverter{}, &review{})
}

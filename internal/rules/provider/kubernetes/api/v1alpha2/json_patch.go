package v1alpha2

import (
	"github.com/goccy/go-json"
	"github.com/wI2L/jsondiff"
	"k8s.io/apimachinery/pkg/types"
)

type jsonPatch struct {
	patchType            types.PatchType
	from                 object
	to                   object
	enableOptimisticLock bool
}

func (p *jsonPatch) Type() types.PatchType { return p.patchType }

func (p *jsonPatch) Data() ([]byte, error) {
	original := p.from
	modified := p.to

	if p.enableOptimisticLock {
		original = p.from.DeepCopyObject().(object) // nolint: forcetypeassert
		modified = p.to.DeepCopyObject().(object)   // nolint: forcetypeassert

		modified.SetResourceVersion(original.GetResourceVersion())
		original.SetResourceVersion("")
	}

	patch, err := jsondiff.Compare(original, modified,
		jsondiff.MarshalFunc(json.Marshal),
		jsondiff.UnmarshalFunc(json.Unmarshal),
		jsondiff.Factorize())
	if err != nil {
		return nil, err
	}

	return json.Marshal(patch)
}

func (p *jsonPatch) ResourceName() string      { return p.from.GetName() }
func (p *jsonPatch) ResourceNamespace() string { return p.from.GetNamespace() }

func NewJSONPatch(from, to object, withOptimisticLock bool) Patch {
	return &jsonPatch{patchType: types.JSONPatchType, from: from, to: to, enableOptimisticLock: withOptimisticLock}
}

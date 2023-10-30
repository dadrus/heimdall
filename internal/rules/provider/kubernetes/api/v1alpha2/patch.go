package v1alpha2

import (
	jsonpatch "github.com/evanphx/json-patch"
	"github.com/goccy/go-json"
	"k8s.io/apimachinery/pkg/types"
)

type Patch interface {
	ResourceName() string
	Type() types.PatchType
	Data() ([]byte, error)
}

type mergeFromPatch struct {
	patchType types.PatchType
	from      *RuleSet
	to        *RuleSet
}

func (p *mergeFromPatch) Type() types.PatchType { return p.patchType }

func (p *mergeFromPatch) Data() ([]byte, error) {
	originalJSON, err := json.Marshal(p.from)
	if err != nil {
		return nil, err
	}

	modifiedJSON, err := json.Marshal(p.to)
	if err != nil {
		return nil, err
	}

	return jsonpatch.CreateMergePatch(originalJSON, modifiedJSON)
}

func (p *mergeFromPatch) ResourceName() string { return p.from.Name }

func MergeFrom(from, to *RuleSet) Patch {
	return &mergeFromPatch{patchType: types.MergePatchType, from: from, to: to}
}

package v1alpha2

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
)

type object interface {
	metav1.Object
	runtime.Object
}

type Patch interface {
	ResourceName() string
	ResourceNamespace() string
	Type() types.PatchType
	Data() ([]byte, error)
}

//go:generate mockery --name RuleSetRepository --structname RuleSetRepositoryMock

type RuleSetRepository interface {
	List(ctx context.Context, opts metav1.ListOptions) (*RuleSetList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Get(ctx context.Context, key types.NamespacedName, opts metav1.GetOptions) (*RuleSet, error)
	PatchStatus(ctx context.Context, patch Patch, opts metav1.PatchOptions) (*RuleSet, error)
}

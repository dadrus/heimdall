package v1alpha3

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

type ruleSetRepositoryImpl struct {
	cl rest.Interface
	ns string
}

func (r *ruleSetRepositoryImpl) List(
	ctx context.Context, opts metav1.ListOptions,
) (*RuleSetList, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}

	result := &RuleSetList{}
	err := r.cl.Get().
		Namespace(r.ns).
		Resource("rulesets").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)

	return result, err
}

func (r *ruleSetRepositoryImpl) Watch(
	ctx context.Context, opts metav1.ListOptions,
) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}

	opts.Watch = true

	return r.cl.Get().
		Namespace(r.ns).
		Resource("rulesets").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

func (r *ruleSetRepositoryImpl) Get(
	ctx context.Context, key types.NamespacedName, opts metav1.GetOptions,
) (*RuleSet, error) {
	result := &RuleSet{}

	err := r.cl.Get().
		Namespace(key.Namespace).
		Resource("rulesets").
		VersionedParams(&opts, scheme.ParameterCodec).
		Name(key.Name).
		Do(ctx).
		Into(result)

	return result, err
}

func (r *ruleSetRepositoryImpl) PatchStatus(
	ctx context.Context, patch Patch, opts metav1.PatchOptions,
) (*RuleSet, error) {
	result := &RuleSet{}

	data, err := patch.Data()
	if err != nil {
		return nil, err
	}

	err = r.cl.Patch(patch.Type()).
		Namespace(r.ns).
		Resource("rulesets").
		Name(patch.ResourceName()).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)

	return result, err
}

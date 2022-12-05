package v1alpha1

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

const (
	GroupName    = "heimdall.dadrus.github.com"
	GroupVersion = "v1alpha1"
)

func addKnownTypes(gv schema.GroupVersion) func(scheme *runtime.Scheme) error {
	return func(scheme *runtime.Scheme) error {
		scheme.AddKnownTypes(gv, &RuleSet{}, &RuleSetList{})
		metav1.AddToGroupVersion(scheme, gv)

		return nil
	}
}

type RuleSetRepository interface {
	List(ctx context.Context, opts metav1.ListOptions) (*RuleSetList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
}

type Client interface {
	RuleSetRepository(namespace string) RuleSetRepository
}

func NewClient(conf *rest.Config) (Client, error) {
	gv := schema.GroupVersion{Group: GroupName, Version: GroupVersion}

	schemeBuilder := runtime.NewSchemeBuilder(addKnownTypes(gv))
	if err := schemeBuilder.AddToScheme(scheme.Scheme); err != nil {
		return nil, err
	}

	config := *conf
	config.ContentConfig.GroupVersion = &gv
	config.APIPath = "/apis"
	config.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	config.UserAgent = rest.DefaultKubernetesUserAgent()

	cl, err := rest.RESTClientFor(&config)
	if err != nil {
		return nil, err
	}

	return &client{cl: cl}, nil
}

type client struct {
	cl rest.Interface
}

func (c *client) RuleSetRepository(namespace string) RuleSetRepository {
	return &repository{
		cl: c.cl,
		ns: namespace,
	}
}

type repository struct {
	cl rest.Interface
	ns string
}

func (r *repository) List(ctx context.Context, opts metav1.ListOptions) (*RuleSetList, error) {
	result := &RuleSetList{}
	err := r.cl.Get().
		Namespace(r.ns).
		Resource("rulesets").
		VersionedParams(&opts, scheme.ParameterCodec).
		Do(ctx).
		Into(result)

	return result, err
}

func (r *repository) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	opts.Watch = true

	return r.cl.Get().
		Namespace(r.ns).
		Resource("rulesets").
		VersionedParams(&opts, scheme.ParameterCodec).
		Watch(ctx)
}

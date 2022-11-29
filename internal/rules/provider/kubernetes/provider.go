package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/go-logr/zerologr"
	"github.com/rs/zerolog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1alpha1"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var (
	ErrNilRuleSet   = errors.New("nil RuleSet")
	ErrNotARuleSet  = errors.New("not a RuleSet")
	ErrBadAuthClass = errors.New("bad authClass in a RuleSet")
)

type provider struct {
	q      event.RuleSetChangedEventQueue
	l      zerolog.Logger
	cl     v1alpha1.Client
	cancel context.CancelFunc
	wg     sync.WaitGroup
	ac     string
}

func newProvider(
	rawConf map[string]any,
	k8sConf *rest.Config,
	queue event.RuleSetChangedEventQueue,
	logger zerolog.Logger,
) (*provider, error) {
	type Config struct {
		AuthClass string `mapstructure:"auth_class"`
	}

	client, err := v1alpha1.NewClient(k8sConf)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed creating client for connecting to kubernetes cluster").
			CausedBy(err)
	}

	var conf Config
	if err = decodeConfig(rawConf, &conf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to decode kubernetes rule provider config").
			CausedBy(err)
	}

	prov := &provider{
		q:  queue,
		l:  logger,
		cl: client,
		ac: x.IfThenElse(len(conf.AuthClass) != 0, conf.AuthClass, DefaultClass),
	}

	return prov, nil
}

func (p *provider) newController(ctx context.Context, namespace string) cache.Controller {
	repository := p.cl.RuleSetRepository(namespace)
	_, controller := cache.NewTransformingInformer(
		&cache.ListWatch{
			ListFunc:  func(opts metav1.ListOptions) (runtime.Object, error) { return repository.List(ctx, opts) },
			WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) { return repository.Watch(ctx, opts) },
		},
		&v1alpha1.RuleSet{},
		0,
		cache.ResourceEventHandlerFuncs{AddFunc: p.addRuleSet, DeleteFunc: p.deleteRuleSet, UpdateFunc: p.updateRuleSet},
		p.filterAuthClass,
	)

	return controller
}

func (p *provider) filterAuthClass(input any) (any, error) {
	if input == nil {
		return nil, ErrNilRuleSet
	}

	rs, ok := input.(*v1alpha1.RuleSet)
	if !ok {
		return nil, ErrNotARuleSet
	}

	if rs.Spec.AuthClassName != p.ac {
		p.l.Info().
			Str("_rule_provider_type", ProviderType).
			Msgf("Ignoring ruleset due to authClassName mismatch (namespace=%s, name=%s, uid=%s)",
				rs.Namespace, rs.Name, rs.UID)

		return nil, ErrBadAuthClass
	}

	return input, nil
}

func (p *provider) Start(_ context.Context) error {
	klog.SetLogger(zerologr.New(&p.l))

	p.l.Info().
		Str("_rule_provider_type", ProviderType).
		Msg("Starting rule definitions provider")

	ctx, cancel := context.WithCancel(context.Background())
	ctx = p.l.With().
		Str("_rule_provider_type", ProviderType).
		Logger().
		WithContext(ctx)

	p.cancel = cancel

	// contextcheck disabled as the context object passed to Start
	// will time out. We need however a fresh context here, which can be
	// canceled
	controller := p.newController(ctx, "") //nolint:contextcheck

	p.wg.Add(1)

	go func() {
		controller.Run(ctx.Done())
		p.wg.Done()
	}()

	return nil
}

func (p *provider) Stop(ctx context.Context) error {
	p.l.Info().
		Str("_rule_provider_type", ProviderType).
		Msg("Tearing down rule provider.")

	p.cancel()

	done := make(chan struct{})

	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		p.l.Warn().
			Str("_rule_provider_type", ProviderType).
			Msg("Graceful tearing down aborted (timed out).")

		return nil
	}
}

func (p *provider) addRuleSet(obj any) {
	rs, ok := obj.(*v1alpha1.RuleSet)
	if !ok {
		return
	}

	p.ruleSetChanged(event.RuleSetChangedEvent{
		Src:        fmt.Sprintf("%s:%s:%s:%s", ProviderType, rs.Namespace, rs.Name, rs.UID),
		ChangeType: event.Create,
		RuleSet:    rs.Spec.Rules,
	})
}

func (p *provider) updateRuleSet(oldObj, newObj any) {
	oldRs, ok := oldObj.(*v1alpha1.RuleSet)
	if !ok {
		return
	}

	newRs, ok := newObj.(*v1alpha1.RuleSet)
	if !ok {
		return
	}

	p.deleteRuleSet(oldRs)
	p.addRuleSet(newRs)
}

func (p *provider) deleteRuleSet(obj any) {
	rs, ok := obj.(*v1alpha1.RuleSet)
	if !ok {
		return
	}

	p.ruleSetChanged(event.RuleSetChangedEvent{
		Src:        fmt.Sprintf("%s:%s:%s:%s", ProviderType, rs.Namespace, rs.Name, rs.UID),
		ChangeType: event.Remove,
	})
}

func (p *provider) ruleSetChanged(evt event.RuleSetChangedEvent) {
	p.l.Info().
		Str("_rule_provider_type", ProviderType).
		Str("_src", evt.Src).
		Str("_type", evt.ChangeType.String()).
		Msg("Rule set changed")
	p.q <- evt
}

package kubernetes

import (
	"context"
	"fmt"
	"sync"

	"github.com/rs/zerolog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/event"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1alpha1"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type provider struct {
	q          event.RuleSetChangedEventQueue
	l          zerolog.Logger
	cl         v1alpha1.Client
	namespaces []string
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

func newProvider(
	rawConf map[string]any,
	k8sConf *rest.Config,
	queue event.RuleSetChangedEventQueue,
	logger zerolog.Logger,
) (*provider, error) {
	type Config struct {
		Namespaces []string          `mapstructure:"namespaces"`
		Labels     map[string]string `mapstructure:"labels"`
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
		q:          queue,
		l:          logger,
		cl:         client,
		namespaces: conf.Namespaces,
	}

	return prov, nil
}

func (p *provider) newController(ctx context.Context, namespace string) cache.Controller {
	_, controller := cache.NewInformer(
		&cache.ListWatch{
			ListFunc: func(opts metav1.ListOptions) (runtime.Object, error) {
				return p.cl.RuleSetRepository(namespace).List(ctx, opts)
			},
			WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
				return p.cl.RuleSetRepository(namespace).Watch(ctx, opts)
			},
		},
		&v1alpha1.RuleSet{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    p.addRuleSet,
			DeleteFunc: p.deleteRuleSet,
			UpdateFunc: p.updateRuleSet,
		},
	)

	return controller
}

func (p *provider) Start(_ context.Context) error {
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
	p.startController(ctx) //nolint:contextcheck

	return nil
}

func (p *provider) startController(ctx context.Context) {
	if len(p.namespaces) == 0 {
		controller := p.newController(ctx, "")

		p.wg.Add(1)

		go func() {
			controller.Run(ctx.Done())
			p.wg.Done()
		}()

		return
	}

	for _, namespace := range p.namespaces {
		controller := p.newController(ctx, namespace)

		p.wg.Add(1)

		go func() {
			controller.Run(ctx.Done())
			p.wg.Done()
		}()
	}
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
	rs, ok := obj.(v1alpha1.RuleSet)
	if !ok {
		return
	}

	p.ruleSetChanged(event.RuleSetChangedEvent{
		Src:        fmt.Sprintf("%s:%s:%s", ProviderType, rs.Namespace, rs.Name),
		ChangeType: event.Create,
		RuleSet:    rs.Spec,
	})
}

func (p *provider) updateRuleSet(oldObj, newObj any) {
	oldRs, ok := oldObj.(v1alpha1.RuleSet)
	if !ok {
		return
	}

	newRs, ok := newObj.(v1alpha1.RuleSet)
	if !ok {
		return
	}

	p.ruleSetChanged(event.RuleSetChangedEvent{
		Src:        fmt.Sprintf("%s:%s:%s", ProviderType, oldRs.Namespace, oldRs.Name),
		ChangeType: event.Remove,
	})

	p.ruleSetChanged(event.RuleSetChangedEvent{
		Src:        fmt.Sprintf("%s:%s:%s", ProviderType, newRs.Namespace, newRs.Name),
		ChangeType: event.Create,
		RuleSet:    newRs.Spec,
	})
}

func (p *provider) deleteRuleSet(obj any) {
	rs, ok := obj.(v1alpha1.RuleSet)
	if !ok {
		return
	}

	p.ruleSetChanged(event.RuleSetChangedEvent{
		Src:        fmt.Sprintf("%s:%s:%s", ProviderType, rs.Namespace, rs.Name),
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

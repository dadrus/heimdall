// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/go-logr/zerologr"
	"github.com/rs/zerolog"
	errors2 "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	config2 "github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/admissioncontroller"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1alpha2"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/slicex"
)

type ConfigFactory func() (*rest.Config, error)

type provider struct {
	p          rule.SetProcessor
	l          zerolog.Logger
	cl         v1alpha2.Client
	adc        admissioncontroller.AdmissionController
	cancel     context.CancelFunc
	configured bool
	stopped    bool
	wg         sync.WaitGroup
	ac         string
	id         string
	store      cache.Store
}

func newProvider(
	logger zerolog.Logger,
	conf *config.Configuration,
	k8sCF ConfigFactory,
	processor rule.SetProcessor,
	factory rule.Factory,
) (*provider, error) {
	rawConf := conf.Rules.Providers.Kubernetes

	if rawConf == nil {
		return &provider{}, nil
	}

	k8sConf, err := k8sCF()
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal,
			"failed to create kubernetes provider").CausedBy(err)
	}

	type Config struct {
		AuthClass string      `mapstructure:"auth_class"`
		TLS       *config.TLS `mapstructure:"tls"`
	}

	client, err := v1alpha2.NewClient(k8sConf)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed creating client for connecting to kubernetes cluster").CausedBy(err)
	}

	var providerConf Config
	if err = decodeConfig(rawConf, &providerConf); err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed to decode kubernetes rule provider config").CausedBy(err)
	}

	logger = logger.With().Str("_provider_type", ProviderType).Logger()
	authClass := x.IfThenElse(len(providerConf.AuthClass) != 0, providerConf.AuthClass, DefaultClass)
	adc := admissioncontroller.New(providerConf.TLS, logger, authClass, factory)
	instanceID, _ := os.Hostname()

	logger.Info().Msg("Rule provider configured.")

	return &provider{
		p:          processor,
		l:          logger,
		cl:         client,
		ac:         authClass,
		adc:        adc,
		id:         x.IfThenElse(len(instanceID) == 0, "unknown", instanceID),
		configured: true,
	}, nil
}

func (p *provider) newController(ctx context.Context, namespace string) (cache.Store, cache.Controller) {
	repository := p.cl.RuleSetRepository(namespace)

	return cache.NewInformer(
		&cache.ListWatch{
			ListFunc:  func(opts metav1.ListOptions) (runtime.Object, error) { return repository.List(ctx, opts) },
			WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) { return repository.Watch(ctx, opts) },
		},
		&v1alpha2.RuleSet{},
		0,
		cache.FilteringResourceEventHandler{
			FilterFunc: p.filter,
			Handler: cache.ResourceEventHandlerFuncs{
				AddFunc:    p.addRuleSet,
				DeleteFunc: p.deleteRuleSet,
				UpdateFunc: p.updateRuleSet,
			},
		},
	)
}

func (p *provider) Start(ctx context.Context) error {
	if !p.configured {
		return nil
	}

	klog.SetLogger(zerologr.New(&p.l))

	p.l.Info().Msg("Starting rule definitions provider")

	newCtx, cancel := context.WithCancel(context.Background())
	newCtx = p.l.With().Logger().WithContext(newCtx)

	p.cancel = cancel

	// contextcheck disabled as the context object passed to Start
	// will time out. We need however a fresh context here, which can be
	// canceled
	store, controller := p.newController(newCtx, "") //nolint:contextcheck
	p.store = store

	p.wg.Add(1)

	go func() {
		controller.Run(newCtx.Done())
		p.wg.Done()
	}()

	return p.adc.Start(ctx)
}

func (p *provider) Stop(ctx context.Context) error {
	if !p.configured || p.stopped {
		return nil
	}

	p.stopped = true
	p.l.Info().Msg("Tearing down rule provider.")

	p.cancel()
	_ = p.adc.Stop(ctx)

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	p.finalize(ctx)

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		p.l.Warn().Msg("Graceful tearing down aborted (timed out).")

		return nil
	}
}

func (p *provider) filter(obj any) bool {
	// should never be of a different type. ok if panics
	rs := obj.(*v1alpha2.RuleSet) // nolint: forcetypeassert

	return rs.Spec.AuthClassName == p.ac
}

func (p *provider) addRuleSet(obj any) {
	if p.stopped {
		return
	}

	p.l.Info().Msg("New rule set received")

	// should never be of a different type. ok if panics
	rs := obj.(*v1alpha2.RuleSet) // nolint: forcetypeassert
	conf := p.toRuleSetConfiguration(rs)

	if err := p.p.OnCreated(conf); err != nil {
		p.l.Warn().Err(err).Str("_src", conf.Source).Msg("Failed creating rule set")

		msg := fmt.Sprintf("%s instance failed loading RuleSet, reason: %s", p.id, err.Error())
		p.updateStatus(context.Background(), rs, metav1.ConditionFalse, v1alpha2.ConditionRuleSetActivationFailed, msg)
	} else {
		msg := fmt.Sprintf("%s instance successfully loaded RuleSet", p.id)
		p.updateStatus(context.Background(), rs, metav1.ConditionTrue, v1alpha2.ConditionRuleSetActive, msg)
	}
}

func (p *provider) updateRuleSet(oldObj, newObj any) {
	if p.stopped {
		return
	}

	// should never be of a different type. ok if panics
	newRS := newObj.(*v1alpha2.RuleSet) // nolint: forcetypeassert
	oldRS := oldObj.(*v1alpha2.RuleSet) // nolint: forcetypeassert

	if oldRS.Generation == newRS.Generation {
		// we're only interested in Spec updates. Changes in metadata or status are not of relevance
		return
	}

	p.l.Info().Msg("Rule set update received")

	conf := p.toRuleSetConfiguration(newRS)

	if err := p.p.OnUpdated(conf); err != nil {
		p.l.Warn().Err(err).Str("_src", conf.Source).Msg("Failed to apply rule set updates")

		msg := fmt.Sprintf("%s instance failed updating RuleSet, reason: %s", p.id, err.Error())
		p.updateStatus(context.Background(), newRS, metav1.ConditionFalse, v1alpha2.ConditionRuleSetActivationFailed, msg)
	} else {
		msg := fmt.Sprintf("%s instance successfully reloaded RuleSet", p.id)
		p.updateStatus(context.Background(), newRS, metav1.ConditionTrue, v1alpha2.ConditionRuleSetActive, msg)
	}
}

func (p *provider) deleteRuleSet(obj any) {
	if p.stopped {
		return
	}

	p.l.Info().Msg("Rule set deletion received")

	// should never be of a different type. ok if panics
	rs := obj.(*v1alpha2.RuleSet) // nolint: forcetypeassert
	conf := p.toRuleSetConfiguration(rs)

	if err := p.p.OnDeleted(conf); err != nil {
		p.l.Warn().Err(err).Str("_src", conf.Source).Msg("Failed deleting rule set")

		msg := fmt.Sprintf("%s instance failed unloading RuleSet, reason: %s", p.id, err.Error())
		p.updateStatus(context.Background(), rs, metav1.ConditionTrue, v1alpha2.ConditionRuleSetUnloadingFailed, msg)
	} else {
		msg := fmt.Sprintf("%s instance dropped RuleSet", p.id)
		p.updateStatus(context.Background(), rs, metav1.ConditionFalse, v1alpha2.ConditionRuleSetUnloaded, msg)
	}
}

func (p *provider) toRuleSetConfiguration(rs *v1alpha2.RuleSet) *config2.RuleSet {
	return &config2.RuleSet{
		MetaData: config2.MetaData{
			Source:  fmt.Sprintf("%s:%s:%s", ProviderType, rs.Namespace, rs.UID),
			ModTime: rs.CreationTimestamp.Time,
		},
		Version: p.mapVersion(rs.APIVersion),
		Name:    rs.Name,
		Rules:   rs.Spec.Rules,
	}
}

func (p *provider) mapVersion(_ string) string {
	// currently the only possible version is v1alpha2, which is mapped to the version "1alpha2" used internally
	return "1alpha2"
}

func (p *provider) updateStatus(
	ctx context.Context,
	rs *v1alpha2.RuleSet,
	status metav1.ConditionStatus,
	reason v1alpha2.ConditionReason,
	msg string,
) {
	rsCopy := rs.DeepCopy()
	repository := p.cl.RuleSetRepository(rsCopy.Namespace)

	p.l.Debug().Msgf("Updating RuleSet status")

	meta.SetStatusCondition(&rsCopy.Status.Conditions, metav1.Condition{
		Type:               fmt.Sprintf("%s/Reconcile", p.id),
		Status:             status,
		ObservedGeneration: rsCopy.Generation,
		Reason:             string(reason),
		Message:            msg,
	})

	if reason == v1alpha2.ConditionControllerStopped || reason == v1alpha2.ConditionRuleSetUnloaded {
		rsCopy.Status.MatchingInstances = slicex.Subtract(rsCopy.Status.MatchingInstances, []string{p.id})
	} else if len(slicex.Filter(rsCopy.Status.MatchingInstances, func(val string) bool { return p.id == val })) == 0 {
		rsCopy.Status.MatchingInstances = append(rsCopy.Status.MatchingInstances, p.id)
	}

	if status == metav1.ConditionTrue &&
		len(slicex.Filter(rsCopy.Status.UsedByInstances, func(val string) bool { return p.id == val })) == 0 {
		rsCopy.Status.UsedByInstances = append(rsCopy.Status.UsedByInstances, p.id)
	} else if status == metav1.ConditionFalse {
		rsCopy.Status.UsedByInstances = slicex.Subtract(rsCopy.Status.UsedByInstances, []string{p.id})
	}

	if _, err := repository.PatchStatus(
		p.l.WithContext(ctx),
		v1alpha2.NewJSONPatch(rs, rsCopy),
		metav1.PatchOptions{},
	); err != nil {
		var statusErr *errors2.StatusError
		if !errors.As(err, &statusErr) {
			p.l.Warn().Err(err).Msgf("Failed updating RuleSet status")

			return
		}

		p.l.Warn().Msgf(statusErr.DebugError())

		switch statusErr.ErrStatus.Code {
		case http.StatusNotFound:
			// resource gone. Nothing can be done
			p.l.Debug().Err(err).Msgf("RuleSet gone")

			return
		case http.StatusConflict, http.StatusUnprocessableEntity:
			p.l.Debug().Err(err).Msgf("New resource version available. Retrieving it.")

			rsKey := types.NamespacedName{Namespace: rsCopy.Namespace, Name: rsCopy.Name}
			if rs, err = repository.Get(ctx, rsKey, metav1.GetOptions{}); err != nil {
				p.l.Warn().Err(err).Msgf("Failed retrieving new RuleSet version for status update")
			} else {
				p.updateStatus(ctx, rs, status, reason, msg)
			}
		default:
			p.l.Warn().Err(err).Msgf("Failed updating RuleSet status")
		}
	} else {
		p.l.Debug().Msgf("RuleSet status updated")
	}
}

func (p *provider) finalize(ctx context.Context) {
	for _, rs := range slicex.Filter(
		// nolint: forcetypeassert
		slicex.Map(p.store.List(), func(s any) *v1alpha2.RuleSet { return s.(*v1alpha2.RuleSet) }),
		func(set *v1alpha2.RuleSet) bool { return set.Spec.AuthClassName == p.ac },
	) {
		p.updateStatus(ctx, rs, metav1.ConditionFalse, v1alpha2.ConditionControllerStopped,
			fmt.Sprintf("%s instance stopped", p.id))
	}
}

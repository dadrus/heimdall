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
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

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
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1alpha3"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/slicex"
)

type ConfigFactory func() (*rest.Config, error)

type provider struct {
	p          rule.SetProcessor
	l          zerolog.Logger
	cl         v1alpha3.Client
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
	rawConf := conf.Providers.Kubernetes

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

	client, err := v1alpha3.NewClient(k8sConf)
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

	return cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: &cache.ListWatch{
			ListFunc:  func(opts metav1.ListOptions) (runtime.Object, error) { return repository.List(ctx, opts) },
			WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) { return repository.Watch(ctx, opts) },
		},
		ObjectType: &v1alpha3.RuleSet{},
		Handler: cache.FilteringResourceEventHandler{
			FilterFunc: p.filter,
			Handler: cache.ResourceEventHandlerFuncs{
				AddFunc:    p.addRuleSet,
				DeleteFunc: p.deleteRuleSet,
				UpdateFunc: p.updateRuleSet,
			},
		},
	})
}

func (p *provider) Start(ctx context.Context) error { //nolint:contextcheck
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
		p.l.Debug().Msg("Starting reconciliation loop")

		controller.Run(newCtx.Done())
		p.wg.Done()

		p.l.Debug().Msg("Reconciliation loop exited")
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
	rs := obj.(*v1alpha3.RuleSet) // nolint: forcetypeassert

	return rs.Spec.AuthClassName == p.ac
}

func (p *provider) addRuleSet(obj any) {
	if p.stopped {
		return
	}

	p.l.Info().Msg("New rule set received")

	// should never be of a different type. ok if panics
	rs := obj.(*v1alpha3.RuleSet) // nolint: forcetypeassert
	conf := p.toRuleSetConfiguration(rs)

	if err := p.p.OnCreated(conf); err != nil {
		p.l.Warn().Err(err).Str("_src", conf.Source).Msg("Failed creating rule set")

		p.updateStatus(
			context.Background(),
			rs,
			metav1.ConditionFalse,
			v1alpha3.ConditionRuleSetActivationFailed,
			1,
			0,
			fmt.Sprintf("%s instance failed loading RuleSet, reason: %s", p.id, err.Error()),
		)
	} else {
		p.updateStatus(
			context.Background(),
			rs,
			metav1.ConditionTrue,
			v1alpha3.ConditionRuleSetActive,
			1,
			1,
			p.id+" instance successfully loaded RuleSet",
		)
	}
}

func (p *provider) updateRuleSet(oldObj, newObj any) {
	if p.stopped {
		return
	}

	// should never be of a different type. ok if panics
	newRS := newObj.(*v1alpha3.RuleSet) // nolint: forcetypeassert
	oldRS := oldObj.(*v1alpha3.RuleSet) // nolint: forcetypeassert

	if oldRS.Generation == newRS.Generation {
		// we're only interested in Spec updates. Changes in metadata or status are not of relevance
		return
	}

	p.l.Info().Msg("Rule set update received")

	conf := p.toRuleSetConfiguration(newRS)

	if err := p.p.OnUpdated(conf); err != nil {
		p.l.Warn().Err(err).Str("_src", conf.Source).Msg("Failed to apply rule set updates")

		p.updateStatus(
			context.Background(),
			newRS,
			metav1.ConditionFalse,
			v1alpha3.ConditionRuleSetActivationFailed,
			0,
			-1,
			fmt.Sprintf("%s instance failed updating RuleSet, reason: %s", p.id, err.Error()),
		)
	} else {
		p.updateStatus(
			context.Background(),
			newRS,
			metav1.ConditionTrue,
			v1alpha3.ConditionRuleSetActive,
			0,
			0,
			p.id+" instance successfully reloaded RuleSet",
		)
	}
}

func (p *provider) deleteRuleSet(obj any) {
	if p.stopped {
		return
	}

	p.l.Info().Msg("Rule set deletion received")

	// should never be of a different type. ok if panics
	rs := obj.(*v1alpha3.RuleSet) // nolint: forcetypeassert
	conf := p.toRuleSetConfiguration(rs)

	if err := p.p.OnDeleted(conf); err != nil {
		p.l.Warn().Err(err).Str("_src", conf.Source).Msg("Failed deleting rule set")

		p.updateStatus(
			context.Background(),
			rs,
			metav1.ConditionTrue,
			v1alpha3.ConditionRuleSetUnloadingFailed,
			0,
			0,
			p.id+" instance failed unloading RuleSet, reason: "+err.Error(),
		)
	} else {
		p.updateStatus(
			context.Background(),
			rs,
			metav1.ConditionFalse,
			v1alpha3.ConditionRuleSetUnloaded,
			-1,
			-1,
			p.id+" instance dropped RuleSet",
		)
	}
}

func (p *provider) toRuleSetConfiguration(rs *v1alpha3.RuleSet) *config2.RuleSet {
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
	// currently the only possible version is v1alpha3, which is mapped to the version "1alpha3" used internally
	return "1alpha3"
}

func (p *provider) updateStatus(
	ctx context.Context,
	rs *v1alpha3.RuleSet,
	status metav1.ConditionStatus,
	reason v1alpha3.ConditionReason,
	matchIncrement int,
	usageIncrement int,
	msg string,
) {
	modRS := rs.DeepCopy()
	repository := p.cl.RuleSetRepository(modRS.Namespace)

	p.l.Debug().Msg("Updating RuleSet status")

	conditionType := p.id + "/Reconciliation"

	if reason == v1alpha3.ConditionControllerStopped || reason == v1alpha3.ConditionRuleSetUnloaded {
		meta.RemoveStatusCondition(&modRS.Status.Conditions, conditionType)
	} else {
		meta.SetStatusCondition(&modRS.Status.Conditions, metav1.Condition{
			Type:               conditionType,
			Status:             status,
			ObservedGeneration: modRS.Generation,
			Reason:             string(reason),
			Message:            msg,
		})
	}

	modRS.Status.ActiveIn = x.IfThenElse(len(modRS.Status.ActiveIn) == 0, "0/0", modRS.Status.ActiveIn)

	usedBy := strings.Split(modRS.Status.ActiveIn, "/")
	loadedBy, _ := strconv.Atoi(usedBy[0])
	matchedBy, _ := strconv.Atoi(usedBy[1])

	modRS.Status.ActiveIn = fmt.Sprintf("%d/%d", loadedBy+usageIncrement, matchedBy+matchIncrement)

	_, err := repository.PatchStatus(
		p.l.WithContext(ctx),
		v1alpha3.NewJSONPatch(rs, modRS, true),
		metav1.PatchOptions{},
	)
	if err == nil {
		p.l.Debug().Msgf("RuleSet status updated")

		return
	}

	// if there is an error, it is always of the below type
	var statusErr *errors2.StatusError

	errors.As(err, &statusErr)

	switch statusErr.ErrStatus.Code {
	case http.StatusNotFound:
		// resource gone. Nothing can be done
		p.l.Debug().Msgf("RuleSet gone")

		return
	case http.StatusConflict, http.StatusUnprocessableEntity:
		p.l.Debug().Err(err).Msgf("New resource version available. Retrieving it.")

		// to avoid cascading reads and writes
		time.Sleep(time.Duration(2*rand.Intn(50)) * time.Millisecond) //nolint:mnd,gosec

		rsKey := types.NamespacedName{Namespace: rs.Namespace, Name: rs.Name}
		if rs, err = repository.Get(ctx, rsKey, metav1.GetOptions{}); err != nil {
			p.l.Warn().Err(err).Msgf("Failed retrieving new RuleSet version for status update")
		} else {
			p.updateStatus(ctx, rs, status, reason, matchIncrement, usageIncrement, msg)
		}
	default:
		p.l.Warn().Err(err).Msgf("Failed updating RuleSet status")
	}
}

func (p *provider) finalize(ctx context.Context) {
	for _, rs := range slicex.Filter(
		// nolint: forcetypeassert
		slicex.Map(p.store.List(), func(s any) *v1alpha3.RuleSet { return s.(*v1alpha3.RuleSet) }),
		func(set *v1alpha3.RuleSet) bool { return set.Spec.AuthClassName == p.ac },
	) {
		p.updateStatus(ctx, rs, metav1.ConditionFalse, v1alpha3.ConditionControllerStopped, -1, -1,
			p.id+" instance stopped")
	}
}

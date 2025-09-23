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

	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/patch"
	"github.com/go-logr/zerologr"
	"github.com/rs/zerolog"
	errors2 "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1beta1"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/webhooks"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/slicex"
)

type ConfigFactory func() (*rest.Config, error)

type ConditionReason string

const (
	ConditionRuleSetActive           ConditionReason = "RuleSetActive"
	ConditionRuleSetActivationFailed ConditionReason = "RuleSetActivationFailed"
	ConditionRuleSetUnloaded         ConditionReason = "RuleSetUnloaded"
	ConditionRuleSetUnloadingFailed  ConditionReason = "RuleSetUnloadingFailed"
	ConditionControllerStopped       ConditionReason = "ControllerStopped"
)

const (
	DefaultClass = "default"
	ProviderType = "kubernetes"
)

type Provider struct {
	p          rule.SetProcessor
	l          zerolog.Logger
	cl         v1beta1.Client
	adc        webhooks.AdmissionController
	cancel     context.CancelFunc
	configured bool
	stopped    bool
	wg         sync.WaitGroup
	ac         string
	id         string
	store      cache.Store
	rsInUse    map[types.UID]bool
}

func NewProvider(app app.Context, k8sCF ConfigFactory, rsp rule.SetProcessor, factory rule.Factory) (*Provider, error) {
	rawConf := app.Config().Providers.Kubernetes
	logger := app.Logger()

	if rawConf == nil {
		return &Provider{}, nil
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

	client, err := v1beta1.NewClient(k8sConf)
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
	adc := webhooks.New(providerConf.TLS, logger, authClass, factory)
	instanceID, _ := os.Hostname()

	logger.Info().Msg("Rule provider configured.")

	return &Provider{
		p:          rsp,
		l:          logger,
		cl:         client,
		ac:         authClass,
		adc:        adc,
		id:         x.IfThenElse(len(instanceID) == 0, "unknown", instanceID),
		configured: true,
		rsInUse:    make(map[types.UID]bool),
	}, nil
}

func (p *Provider) Start(ctx context.Context) error {
	if !p.configured {
		return nil
	}

	klog.SetLogger(zerologr.New(&p.l))
	p.l.Info().Msg("Starting rule provider")

	ctx, p.cancel = context.WithCancel(p.l.WithContext(context.WithoutCancel(ctx)))
	store, controller := p.newController(ctx, "")
	p.store = store

	p.wg.Add(1)

	go func() {
		p.l.Info().Msg("Starting reconciliation loop")

		controller.RunWithContext(ctx)
		p.wg.Done()

		p.l.Info().Msg("Reconciliation loop exited")
	}()

	return p.adc.Start(ctx)
}

func (p *Provider) Stop(ctx context.Context) error {
	if !p.configured || p.stopped {
		return nil
	}

	ctx = p.l.WithContext(ctx)

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

func (p *Provider) newController(ctx context.Context, namespace string) (cache.Store, cache.Controller) {
	repository := p.cl.Repository(namespace)

	return cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: &cache.ListWatch{
			ListWithContextFunc: func(ctx context.Context, options metav1.ListOptions) (runtime.Object, error) {
				return repository.List(ctx, options)
			},
			WatchFuncWithContext: repository.Watch,
		},
		ObjectType: &v1beta1.RuleSet{},
		Handler: cache.FilteringResourceEventHandler{
			FilterFunc: p.filter,
			Handler: cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj any) { p.addRuleSet(ctx, obj) },
				DeleteFunc: func(obj any) { p.deleteRuleSet(ctx, obj) },
				UpdateFunc: func(oldObj, newObj any) { p.updateRuleSet(ctx, oldObj, newObj) },
			},
		},
		ResyncPeriod: 10 * time.Minute,
	})
}

func (p *Provider) filter(obj any) bool {
	// should never be of a different type. ok if panics
	rs := obj.(*v1beta1.RuleSet) // nolint: forcetypeassert

	return rs.Spec.AuthClassName == p.ac
}

func (p *Provider) addRuleSet(ctx context.Context, obj any) {
	if p.stopped {
		return
	}

	// should never be of a different type. ok if panics
	rs := obj.(*v1beta1.RuleSet) // nolint: forcetypeassert
	conf := rs.AsConfig()
	logger := zerolog.Ctx(ctx).With().Str("_src", conf.Source).Logger()
	ctx = logger.WithContext(ctx)

	logger.Info().Msg("New rule set received")

	if err := p.p.OnCreated(ctx, conf); err != nil {
		logger.Warn().Err(err).Msg("Failed loading rule set")

		p.rsInUse[rs.UID] = false

		p.updateStatus(
			ctx,
			rs,
			metav1.ConditionFalse,
			ConditionRuleSetActivationFailed,
			1,
			0,
			p.id+" instance failed loading RuleSet, reason: "+err.Error(),
		)
	} else {
		logger.Info().Msg("Rule set loaded")

		p.rsInUse[rs.UID] = true

		p.updateStatus(
			ctx,
			rs,
			metav1.ConditionTrue,
			ConditionRuleSetActive,
			1,
			1,
			p.id+" instance successfully loaded RuleSet",
		)
	}
}

func (p *Provider) updateRuleSet(ctx context.Context, oldObj, newObj any) {
	if p.stopped {
		return
	}

	// should never be of a different type. ok if panics
	newRS := newObj.(*v1beta1.RuleSet) // nolint: forcetypeassert
	oldRS := oldObj.(*v1beta1.RuleSet) // nolint: forcetypeassert

	if oldRS.Generation == newRS.Generation {
		// we're only interested in Spec updates. Changes in metadata or status are not of relevance
		return
	}

	conf := newRS.AsConfig()
	inUse, known := p.rsInUse[newRS.UID]
	logger := zerolog.Ctx(ctx).With().Str("_src", conf.Source).Logger()
	ctx = logger.WithContext(ctx)

	logger.Info().Msg("Rule set update received")

	if err := p.p.OnUpdated(ctx, conf); err != nil {
		logger.Warn().Err(err).Msg("Failed to apply rule set updates")

		statusIncrement := x.IfThenElse(known && inUse, -1, 0)

		if !known || inUse {
			p.rsInUse[newRS.UID] = false
		}

		p.updateStatus(
			ctx,
			newRS,
			metav1.ConditionFalse,
			ConditionRuleSetActivationFailed,
			0,
			statusIncrement,
			p.id+" instance failed updating RuleSet, reason: "+err.Error(),
		)
	} else {
		logger.Info().Msg("Rule set updates applied")

		statusIncrement := x.IfThenElse(known && inUse, 0, 1)

		if statusIncrement == 1 {
			p.rsInUse[newRS.UID] = true
		}

		p.updateStatus(
			ctx,
			newRS,
			metav1.ConditionTrue,
			ConditionRuleSetActive,
			0,
			statusIncrement,
			p.id+" instance successfully reloaded RuleSet",
		)
	}
}

func (p *Provider) deleteRuleSet(ctx context.Context, obj any) {
	if p.stopped {
		return
	}

	// should never be of a different type. ok if panics
	rs := obj.(*v1beta1.RuleSet) // nolint: forcetypeassert
	conf := rs.AsConfig()
	inUse, known := p.rsInUse[rs.UID]
	logger := zerolog.Ctx(ctx).With().Str("_src", conf.Source).Logger()
	ctx = logger.WithContext(ctx)

	logger.Info().Msg("Rule set deletion received")

	if err := p.p.OnDeleted(ctx, conf); err != nil {
		logger.Warn().Err(err).Msg("Failed deleting rule set")

		p.updateStatus(
			ctx,
			rs,
			metav1.ConditionTrue,
			ConditionRuleSetUnloadingFailed,
			0,
			0,
			p.id+" instance failed unloading RuleSet, reason: "+err.Error(),
		)
	} else {
		logger.Info().Msg("Rule set deleted")

		delete(p.rsInUse, rs.UID)

		p.updateStatus(
			ctx,
			rs,
			metav1.ConditionFalse,
			ConditionRuleSetUnloaded,
			-1,
			x.IfThenElse(known && inUse, -1, 0),
			p.id+" instance dropped RuleSet",
		)
	}
}

func (p *Provider) updateStatus(
	ctx context.Context,
	rs *v1beta1.RuleSet,
	status metav1.ConditionStatus,
	reason ConditionReason,
	matchIncrement int,
	usageIncrement int,
	msg string,
) {
	logger := zerolog.Ctx(ctx)
	modRS := rs.DeepCopy()
	repository := p.cl.Repository(modRS.Namespace)
	conditionType := p.id + "/Reconciliation"

	logger.Debug().Msg("Updating RuleSet status")

	if reason == ConditionControllerStopped || reason == ConditionRuleSetUnloaded {
		meta.RemoveStatusCondition(&modRS.Status.Conditions, conditionType)
	} else {
		// 1024 is currently the length constraint configured in the ruleset CRD for the status message
		const (
			maxStatusMessageLength = 1024
			messageSuffix          = " (... trimmed)"
		)

		if len(msg) > maxStatusMessageLength {
			msg = msg[:maxStatusMessageLength-len(messageSuffix)] + messageSuffix
		}

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

	_, err := repository.PatchStatus(ctx, patch.NewJSONPatch(rs, modRS, true), metav1.PatchOptions{})
	if err == nil {
		logger.Debug().Msgf("RuleSet status updated")

		return
	}

	// if there is an error, it is always of the below type
	var statusErr *errors2.StatusError
	if !errors.As(err, &statusErr) {
		logger.Error().Err(err).
			Msgf("Could not update RuleSet status due to an implementation error. Please file a bug report.")

		return
	}

	switch statusErr.ErrStatus.Code {
	case http.StatusNotFound:
		// resource gone. Nothing can be done. Typically happens on resource delete
		logger.Debug().Msgf("RuleSet gone")

		return
	case http.StatusConflict:
		logger.Debug().Err(err).Msgf("New resource version available. Retrieving it.")

		// to avoid cascading reads and writes
		time.Sleep(time.Duration(2*rand.Intn(50)) * time.Millisecond) //nolint:mnd,gosec

		rsKey := types.NamespacedName{Namespace: rs.Namespace, Name: rs.Name}
		if rs, err = repository.Get(ctx, rsKey, metav1.GetOptions{}); err != nil {
			logger.Warn().Err(err).Msgf("Failed retrieving new RuleSet version for status update")
		} else {
			p.updateStatus(ctx, rs, status, reason, matchIncrement, usageIncrement, msg)
		}
	case http.StatusUnprocessableEntity:
		logger.Error().Err(err).
			Msgf("Could not update RuleSet status due to an implementation error. Please file a bug report.")
	default:
		logger.Warn().Err(err).Msgf("Failed updating RuleSet status")
	}
}

func (p *Provider) finalize(ctx context.Context) {
	for _, rs := range slicex.Filter(
		// nolint: forcetypeassert
		slicex.Map(p.store.List(), func(s any) *v1beta1.RuleSet { return s.(*v1beta1.RuleSet) }),
		func(set *v1beta1.RuleSet) bool { return set.Spec.AuthClassName == p.ac },
	) {
		p.updateStatus(ctx, rs, metav1.ConditionFalse, ConditionControllerStopped, -1, -1,
			p.id+" instance stopped")
	}
}

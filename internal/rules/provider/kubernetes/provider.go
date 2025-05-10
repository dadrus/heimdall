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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	config2 "github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/admissioncontroller"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1alpha4"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/slicex"
)

type ConfigFactory func() (*rest.Config, error)

type Provider struct {
	p          rule.SetProcessor
	l          zerolog.Logger
	cl         v1alpha4.Client
	adc        admissioncontroller.AdmissionController
	cancel     context.CancelFunc
	configured bool
	stopped    bool
	wg         sync.WaitGroup
	ac         string
	id         string
	store      cache.Store
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

	client, err := v1alpha4.NewClient(k8sConf)
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

	return &Provider{
		p:          rsp,
		l:          logger,
		cl:         client,
		ac:         authClass,
		adc:        adc,
		id:         x.IfThenElse(len(instanceID) == 0, "unknown", instanceID),
		configured: true,
	}, nil
}

func (p *Provider) newController(ctx context.Context, namespace string) (cache.Store, cache.Controller) {
	repository := p.cl.RuleSetRepository(namespace)

	return cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: &cache.ListWatch{
			ListWithContextFunc:  repository.List,
			WatchFuncWithContext: repository.Watch,
		},
		ObjectType: &v1alpha4.RuleSet{},
		Handler: cache.FilteringResourceEventHandler{
			FilterFunc: p.filter,
			Handler: cache.ResourceEventHandlerFuncs{
				AddFunc:    func(obj any) { p.addRuleSet(ctx, obj) },
				DeleteFunc: func(obj any) { p.deleteRuleSet(ctx, obj) },
				UpdateFunc: func(oldObj, newObj any) { p.updateRuleSet(ctx, oldObj, newObj) },
			},
		},
	})
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

func (p *Provider) filter(obj any) bool {
	// should never be of a different type. ok if panics
	rs := obj.(*v1alpha4.RuleSet) // nolint: forcetypeassert

	return rs.Spec.AuthClassName == p.ac
}

func (p *Provider) addRuleSet(ctx context.Context, obj any) {
	if p.stopped {
		return
	}

	logger := zerolog.Ctx(ctx)
	logger.Info().Msg("New rule set received")

	// should never be of a different type. ok if panics
	rs := obj.(*v1alpha4.RuleSet) // nolint: forcetypeassert
	conf := p.toRuleSetConfiguration(rs)

	if err := p.p.OnCreated(ctx, conf); err != nil {
		logger.Warn().Err(err).Str("_src", conf.Source).Msg("Failed creating rule set")

		p.updateStatus(
			ctx,
			rs,
			metav1.ConditionFalse,
			v1alpha4.ConditionRuleSetActivationFailed,
			1,
			0,
			fmt.Sprintf("%s instance failed loading RuleSet, reason: %s", p.id, err.Error()),
		)
	} else {
		p.updateStatus(
			ctx,
			rs,
			metav1.ConditionTrue,
			v1alpha4.ConditionRuleSetActive,
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

	logger := zerolog.Ctx(ctx)

	// should never be of a different type. ok if panics
	newRS := newObj.(*v1alpha4.RuleSet) // nolint: forcetypeassert
	oldRS := oldObj.(*v1alpha4.RuleSet) // nolint: forcetypeassert

	if oldRS.Generation == newRS.Generation {
		// we're only interested in Spec updates. Changes in metadata or status are not of relevance
		return
	}

	logger.Info().Msg("Rule set update received")

	conf := p.toRuleSetConfiguration(newRS)

	if err := p.p.OnUpdated(ctx, conf); err != nil {
		logger.Warn().Err(err).Str("_src", conf.Source).Msg("Failed to apply rule set updates")

		p.updateStatus(
			ctx,
			newRS,
			metav1.ConditionFalse,
			v1alpha4.ConditionRuleSetActivationFailed,
			0,
			-1,
			fmt.Sprintf("%s instance failed updating RuleSet, reason: %s", p.id, err.Error()),
		)
	} else {
		p.updateStatus(
			ctx,
			newRS,
			metav1.ConditionTrue,
			v1alpha4.ConditionRuleSetActive,
			0,
			0,
			p.id+" instance successfully reloaded RuleSet",
		)
	}
}

func (p *Provider) deleteRuleSet(ctx context.Context, obj any) {
	if p.stopped {
		return
	}

	logger := zerolog.Ctx(ctx)
	logger.Info().Msg("Rule set deletion received")

	// should never be of a different type. ok if panics
	rs := obj.(*v1alpha4.RuleSet) // nolint: forcetypeassert
	conf := p.toRuleSetConfiguration(rs)

	if err := p.p.OnDeleted(ctx, conf); err != nil {
		logger.Warn().Err(err).Str("_src", conf.Source).Msg("Failed deleting rule set")

		p.updateStatus(
			ctx,
			rs,
			metav1.ConditionTrue,
			v1alpha4.ConditionRuleSetUnloadingFailed,
			0,
			0,
			p.id+" instance failed unloading RuleSet, reason: "+err.Error(),
		)
	} else {
		p.updateStatus(
			ctx,
			rs,
			metav1.ConditionFalse,
			v1alpha4.ConditionRuleSetUnloaded,
			-1,
			-1,
			p.id+" instance dropped RuleSet",
		)
	}
}

func (p *Provider) toRuleSetConfiguration(rs *v1alpha4.RuleSet) *config2.RuleSet {
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

func (p *Provider) mapVersion(_ string) string {
	// currently the only possible version is v1alpha4, which is mapped to the version "1alpha4" used internally
	return "1alpha4"
}

func (p *Provider) updateStatus(
	ctx context.Context,
	rs *v1alpha4.RuleSet,
	status metav1.ConditionStatus,
	reason v1alpha4.ConditionReason,
	matchIncrement int,
	usageIncrement int,
	msg string,
) {
	modRS := rs.DeepCopy()
	repository := p.cl.RuleSetRepository(modRS.Namespace)

	logger := zerolog.Ctx(ctx)
	logger.Debug().Msg("Updating RuleSet status")

	conditionType := p.id + "/Reconciliation"

	if reason == v1alpha4.ConditionControllerStopped || reason == v1alpha4.ConditionRuleSetUnloaded {
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
		ctx,
		v1alpha4.NewJSONPatch(rs, modRS, true),
		metav1.PatchOptions{},
	)
	if err == nil {
		logger.Debug().Msgf("RuleSet status updated")

		return
	}

	// if there is an error, it is always of the below type
	var statusErr *errors2.StatusError

	errors.As(err, &statusErr)

	switch statusErr.ErrStatus.Code {
	case http.StatusNotFound:
		// resource gone. Nothing can be done
		logger.Debug().Msgf("RuleSet gone")

		return
	case http.StatusConflict, http.StatusUnprocessableEntity:
		logger.Debug().Err(err).Msgf("New resource version available. Retrieving it.")

		// to avoid cascading reads and writes
		time.Sleep(time.Duration(2*rand.Intn(50)) * time.Millisecond) //nolint:mnd,gosec

		rsKey := types.NamespacedName{Namespace: rs.Namespace, Name: rs.Name}
		if rs, err = repository.Get(ctx, rsKey, metav1.GetOptions{}); err != nil {
			logger.Warn().Err(err).Msgf("Failed retrieving new RuleSet version for status update")
		} else {
			p.updateStatus(ctx, rs, status, reason, matchIncrement, usageIncrement, msg)
		}
	default:
		logger.Warn().Err(err).Msgf("Failed updating RuleSet status")
	}
}

func (p *Provider) finalize(ctx context.Context) {
	for _, rs := range slicex.Filter(
		// nolint: forcetypeassert
		slicex.Map(p.store.List(), func(s any) *v1alpha4.RuleSet { return s.(*v1alpha4.RuleSet) }),
		func(set *v1alpha4.RuleSet) bool { return set.Spec.AuthClassName == p.ac },
	) {
		p.updateStatus(ctx, rs, metav1.ConditionFalse, v1alpha4.ConditionControllerStopped, -1, -1,
			p.id+" instance stopped")
	}
}

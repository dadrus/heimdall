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
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/zerologr"
	"github.com/rs/zerolog"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
)

type conditionReason string

const (
	authClassMismatch conditionReason = "AuthClassMismatch"
	loaded            conditionReason = "Loaded"
	invalidRuleSet    conditionReason = "Invalid"
)

type ConfigFactory func() (*rest.Config, error)

type provider struct {
	p          rule.SetProcessor
	l          zerolog.Logger
	cl         v1alpha2.Client
	adc        admissioncontroller.AdmissionController
	cancel     context.CancelFunc
	configured bool
	wg         sync.WaitGroup
	ac         string
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
			"failed to create kubernetes provider").
			CausedBy(err)
	}

	type Config struct {
		AuthClass string      `mapstructure:"auth_class"`
		TLS       *config.TLS `mapstructure:"tls"`
	}

	client, err := v1alpha2.NewClient(k8sConf)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrConfiguration,
			"failed creating client for connecting to kubernetes cluster").
			CausedBy(err)
	}

	var providerConf Config
	if err = decodeConfig(rawConf, &providerConf); err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrConfiguration, "failed to decode kubernetes rule provider config").
			CausedBy(err)
	}

	logger = logger.With().Str("_provider_type", ProviderType).Logger()
	authClass := x.IfThenElse(len(providerConf.AuthClass) != 0, providerConf.AuthClass, DefaultClass)
	adc := admissioncontroller.New(providerConf.TLS, logger, authClass, factory)

	logger.Info().Msg("Rule provider configured.")

	return &provider{
		p:          processor,
		l:          logger,
		cl:         client,
		ac:         authClass,
		adc:        adc,
		configured: true,
	}, nil
}

func (p *provider) newController(ctx context.Context, namespace string) cache.Controller {
	repository := p.cl.RuleSetRepository(namespace)
	_, controller := cache.NewInformer(
		&cache.ListWatch{
			ListFunc:  func(opts metav1.ListOptions) (runtime.Object, error) { return repository.List(ctx, opts) },
			WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) { return repository.Watch(ctx, opts) },
		},
		&v1alpha2.RuleSet{},
		0,
		cache.ResourceEventHandlerFuncs{AddFunc: p.addRuleSet, DeleteFunc: p.deleteRuleSet, UpdateFunc: p.updateRuleSet},
	)

	return controller
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
	controller := p.newController(newCtx, "") //nolint:contextcheck

	p.wg.Add(1)

	go func() {
		controller.Run(newCtx.Done())
		p.wg.Done()
	}()

	return p.adc.Start(ctx)
}

func (p *provider) Stop(ctx context.Context) error {
	if !p.configured {
		return nil
	}

	p.l.Info().Msg("Tearing down rule provider.")

	p.cancel()
	_ = p.adc.Stop(ctx)

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		p.l.Warn().Msg("Graceful tearing down aborted (timed out).")

		return nil
	}
}

func (p *provider) addRuleSet(obj any) {
	// should never be of a different type. ok if panics
	rs := obj.(*v1alpha2.RuleSet) // nolint: forcetypeassert

	if rs.Spec.AuthClassName != p.ac {
		p.l.Debug().
			Msgf("Ignoring ruleset creation due to authClassName mismatch (namespace=%s, name=%s, uid=%s)",
				rs.Namespace, rs.Name, rs.UID)

		p.updateStatus(
			rs,
			v1alpha2.RuleSetStatePending,
			authClassMismatch,
			fmt.Sprintf("RuleSet ignored due to auth_class='%s' - authClassName='%s' mismatch",
				p.ac, rs.Spec.AuthClassName))

		return
	}

	conf := &config2.RuleSet{
		MetaData: config2.MetaData{
			Source:  fmt.Sprintf("%s:%s:%s", ProviderType, rs.Namespace, rs.UID),
			ModTime: rs.CreationTimestamp.Time,
		},
		Version: p.mapVersion(rs.APIVersion),
		Name:    rs.Name,
		Rules:   rs.Spec.Rules,
	}

	p.l.Info().Msg("New rule set received")

	p.l.Debug().Str("_src", conf.Source).
		Msgf("Rule set resource version mapped from '%s' to '%s'", rs.APIVersion, conf.Version)

	if err := p.p.OnCreated(conf); err != nil {
		p.l.Warn().Err(err).Str("_src", conf.Source).Msg("Failed creating rule set")
		p.updateStatus(
			rs,
			v1alpha2.RuleSetStateFailed,
			invalidRuleSet,
			err.Error())
	} else {
		p.l.Info().Str("_src", conf.Source).Msg("Rule set created")
		p.updateStatus(
			rs,
			v1alpha2.RuleSetStateActive,
			loaded,
			"RuleSet successfully loaded",
		)
	}
}

func (p *provider) updateRuleSet(_, newObj any) {
	// should never be of a different type. ok if panics
	rs := newObj.(*v1alpha2.RuleSet) // nolint: forcetypeassert

	if rs.Spec.AuthClassName != p.ac {
		p.l.Debug().
			Msgf("Ignoring ruleset update due to authClassName mismatch (namespace=%s, name=%s, uid=%s)",
				rs.Namespace, rs.Name, rs.UID)

		p.updateStatus(
			rs,
			v1alpha2.RuleSetStatePending,
			authClassMismatch,
			fmt.Sprintf("RuleSet ignored due to auth_class='%s' - authClassName='%s' mismatch",
				p.ac, rs.Spec.AuthClassName))

		return
	}

	conf := &config2.RuleSet{
		MetaData: config2.MetaData{
			Source:  fmt.Sprintf("%s:%s:%s", ProviderType, rs.Namespace, rs.UID),
			ModTime: rs.CreationTimestamp.Time,
		},
		Version: p.mapVersion(rs.APIVersion),
		Name:    rs.Name,
		Rules:   rs.Spec.Rules,
	}

	p.l.Info().Msg("Rule set update received")

	p.l.Debug().Str("_src", conf.Source).
		Msgf("Rule set resource version mapped from '%s' to '%s'", rs.APIVersion, conf.Version)

	if err := p.p.OnUpdated(conf); err != nil {
		p.l.Warn().Err(err).Str("_src", conf.Source).Msg("Failed to apply rule set updates")
	} else {
		p.l.Info().Str("_src", conf.Source).Msg("Rule set updated")
	}
}

func (p *provider) deleteRuleSet(obj any) {
	// should never be of a different type. ok if panics
	rs := obj.(*v1alpha2.RuleSet) // nolint: forcetypeassert

	if rs.Spec.AuthClassName != p.ac {
		p.l.Debug().
			Msgf("Ignoring ruleset deletion due to authClassName mismatch (namespace=%s, name=%s, uid=%s)",
				rs.Namespace, rs.Name, rs.UID)

		return
	}

	conf := &config2.RuleSet{
		MetaData: config2.MetaData{
			Source:  fmt.Sprintf("%s:%s:%s", ProviderType, rs.Namespace, rs.UID),
			ModTime: time.Now(),
		},
		Version: p.mapVersion(rs.APIVersion),
		Name:    rs.Name,
	}

	p.l.Info().Msg("Rule set deletion received")

	p.l.Debug().Str("_src", conf.Source).
		Msgf("Rule set resource version mapped from '%s' to '%s'", rs.APIVersion, conf.Version)

	if err := p.p.OnDeleted(conf); err != nil {
		p.l.Warn().Err(err).Str("_src", conf.Source).Msg("Failed deleting rule set")
	} else {
		p.l.Info().Str("_src", conf.Source).Msg("Rule set deleted")
	}
}

func (p *provider) mapVersion(_ string) string {
	// currently the only possible version is v1alpha2, which is mapped to the version "1alpha2" used internally
	return "1alpha2"
}

func (p *provider) updateStatus(
	rs *v1alpha2.RuleSet,
	state v1alpha2.RuleSetStatusEnum,
	reason conditionReason,
	msg string,
) {
	rsCopy := rs.DeepCopy()
	conditionStatus := x.IfThenElse(state == v1alpha2.RuleSetStateActive, metav1.ConditionTrue, metav1.ConditionFalse)

	meta.SetStatusCondition(&rsCopy.Status.Conditions, metav1.Condition{
		Type:               rsCopy.Name,
		Status:             conditionStatus,
		ObservedGeneration: rsCopy.Generation,
		Reason:             string(reason),
		Message:            msg,
	})

	if state != v1alpha2.RuleSetStatePending {
		rsCopy.Status.Status = state
	}

	repository := p.cl.RuleSetRepository(rsCopy.Namespace)
	if _, err := repository.UpdateStatus(context.Background(), rsCopy, metav1.UpdateOptions{}); err != nil {
		p.l.Warn().Err(err).Msg("Failed updating RuleSet status")
	}
}

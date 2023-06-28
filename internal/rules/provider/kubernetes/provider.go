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
	"sync"
	"time"

	"github.com/go-logr/zerologr"
	"github.com/rs/zerolog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	config2 "github.com/dadrus/heimdall/internal/rules/config"
	"github.com/dadrus/heimdall/internal/rules/provider/kubernetes/api/v1alpha2"
	"github.com/dadrus/heimdall/internal/rules/rule"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var ErrBadAuthClass = errors.New("bad authClass in a RuleSet")

type ConfigFactory func() (*rest.Config, error)

type provider struct {
	p          rule.SetProcessor
	l          zerolog.Logger
	cl         v1alpha2.Client
	cancel     context.CancelFunc
	configured bool
	wg         sync.WaitGroup
	ac         string
}

func newProvider(
	conf *config.Configuration,
	k8sCF ConfigFactory,
	processor rule.SetProcessor,
	logger zerolog.Logger,
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
		AuthClass string `mapstructure:"auth_class"`
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

	logger.Info().Msg("Rule provider configured.")

	return &provider{
		p:          processor,
		l:          logger,
		cl:         client,
		ac:         x.IfThenElse(len(providerConf.AuthClass) != 0, providerConf.AuthClass, DefaultClass),
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

func (p *provider) Start(_ context.Context) error {
	if !p.configured {
		return nil
	}

	klog.SetLogger(zerologr.New(&p.l))

	p.l.Info().Msg("Starting rule definitions provider")

	ctx, cancel := context.WithCancel(context.Background())
	ctx = p.l.With().Logger().WithContext(ctx)

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
	if !p.configured {
		return nil
	}

	p.l.Info().Msg("Tearing down rule provider.")

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
		p.l.Warn().Msg("Graceful tearing down aborted (timed out).")

		return nil
	}
}

func (p *provider) updateRuleSet(_, newObj any) {
	// should never be of a different type. ok if panics
	rs := newObj.(*v1alpha2.RuleSet) // nolint: forcetypeassert

	if rs.Spec.AuthClassName != p.ac {
		p.l.Info().
			Msgf("Ignoring ruleset creation due to authClassName mismatch (namespace=%s, name=%s, uid=%s)",
				rs.Namespace, rs.Name, rs.UID)

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

func (p *provider) addRuleSet(obj any) {
	// should never be of a different type. ok if panics
	rs := obj.(*v1alpha2.RuleSet) // nolint: forcetypeassert

	if rs.Spec.AuthClassName != p.ac {
		p.l.Info().
			Msgf("Ignoring ruleset creation due to authClassName mismatch (namespace=%s, name=%s, uid=%s)",
				rs.Namespace, rs.Name, rs.UID)

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
	} else {
		p.l.Info().Str("_src", conf.Source).Msg("Rule set created")
	}
}

func (p *provider) deleteRuleSet(obj any) {
	// should never be of a different type. ok if panics
	rs := obj.(*v1alpha2.RuleSet) // nolint: forcetypeassert

	if rs.Spec.AuthClassName != p.ac {
		p.l.Info().
			Msgf("Ignoring ruleset creation due to authClassName mismatch (namespace=%s, name=%s, uid=%s)",
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

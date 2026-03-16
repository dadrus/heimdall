// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
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

package metrics

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/cache/types"
	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

const (
	cacheResultKey  = attribute.Key("cache.result")
	cacheBackendKey = attribute.Key("cache.backend")
)

type Cache struct {
	c         types.Cache
	gc        metric.Int64Counter
	sc        metric.Int64Counter
	okAttrs   attribute.Set
	hitAttrs  attribute.Set
	missAttrs attribute.Set
	errAttrs  attribute.Set
}

func (c *Cache) Type() string                    { return c.c.Type() }
func (c *Cache) Start(ctx context.Context) error { return c.c.Start(ctx) }
func (c *Cache) Stop(ctx context.Context) error  { return c.c.Stop(ctx) }

func (c *Cache) Get(ctx context.Context, key string) ([]byte, error) {
	var (
		item  []byte
		err   error
		attrs attribute.Set
	)

	item, err = c.c.Get(ctx, key)
	if err != nil {
		if errors.Is(err, types.ErrNoEntry) {
			attrs = c.missAttrs
		} else {
			attrs = c.errAttrs
		}
	} else {
		attrs = c.hitAttrs
	}

	c.collect(ctx, c.gc, attrs)

	return item, err
}

func (c *Cache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	var attrs attribute.Set

	err := c.c.Set(ctx, key, value, ttl)
	if err != nil {
		attrs = c.errAttrs
	} else {
		attrs = c.okAttrs
	}

	c.collect(ctx, c.sc, attrs)

	return err
}

func (c *Cache) collect(ctx context.Context, counter metric.Int64Counter, attrs attribute.Set) {
	if counter.Enabled(ctx) {
		counter.Add(ctx, 1, metric.WithAttributeSet(attrs))
	}
}

func Decorate(ctx app.Context, cache types.Cache) (types.Cache, error) {
	getRequestsCounter, err := ctx.Meter().Int64Counter("cache.get.requests",
		metric.WithDescription("Total number of cache get requests"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
			"failed creating cache.get.requests counter").CausedBy(err)
	}

	setRequestsCounter, err := ctx.Meter().Int64Counter("cache.set.requests",
		metric.WithDescription("Total number of cache set requests"),
		metric.WithUnit("{request}"),
	)
	if err != nil {
		return nil, errorchain.NewWithMessagef(pipeline.ErrConfiguration,
			"failed creating cache.set.requests counter").CausedBy(err)
	}

	cacheType := cache.Type()

	return &Cache{
		c:  cache,
		gc: getRequestsCounter,
		sc: setRequestsCounter,
		okAttrs: attribute.NewSet(
			cacheResultKey.String("success"),
			cacheBackendKey.String(cacheType),
		),
		hitAttrs: attribute.NewSet(
			cacheResultKey.String("hit"),
			cacheBackendKey.String(cacheType),
		),
		missAttrs: attribute.NewSet(
			cacheResultKey.String("miss"),
			cacheBackendKey.String(cacheType),
		),
		errAttrs: attribute.NewSet(
			cacheResultKey.String("error"),
			cacheBackendKey.String(cacheType),
		),
	}, nil
}

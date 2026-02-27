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

package semconv

import (
	"context"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	recOptPool = &sync.Pool{New: func() any { return &[]metric.RecordOption{} }}  //nolint:gochecknoglobals
	obsOptPool = &sync.Pool{New: func() any { return &[]metric.ObserveOption{} }} //nolint:gochecknoglobals
)

type RuleExecutionDuration struct {
	metric.Float64Histogram
}

var newExecutionRuleDurationOpts = []metric.Float64HistogramOption{ //nolint:gochecknoglobals
	metric.WithDescription("Duration of rule executions"),
	metric.WithUnit("s"),
	metric.WithExplicitBucketBoundaries(
		0.00001, 0.00005, // 10, 50µs
		0.0001, 0.00025, 0.0005, 0.00075, // 100, 250, 500, 750µs
		0.001, 0.0025, 0.005, 0.0075, // 1, 2.5, 5, 7.5ms
		0.01, 0.025, 0.05, 0.075, // 10, 25, 50, 75ms
		0.1, 0.25, 0.5, 0.75, // 100, 250, 500 750 ms
		1.0, 2.0, 5.0, // 1, 2, 5
	),
}

func NewRuleExecutionDuration(
	meter metric.Meter,
	opt ...metric.Float64HistogramOption,
) (RuleExecutionDuration, error) {
	if len(opt) == 0 {
		opt = newExecutionRuleDurationOpts
	} else {
		opt = append(opt, newExecutionRuleDurationOpts...)
	}

	histogram, err := meter.Float64Histogram("rule.execution.duration", opt...)
	if err != nil {
		return RuleExecutionDuration{}, err
	}

	return RuleExecutionDuration{histogram}, nil
}

func (m RuleExecutionDuration) Inst() metric.Float64Histogram {
	return m.Float64Histogram
}

func (RuleExecutionDuration) Name() string {
	return "rule.execution.duration"
}

func (RuleExecutionDuration) Unit() string {
	return "s"
}

func (RuleExecutionDuration) Description() string { return "Duration of rule executions" }

func (m RuleExecutionDuration) Record(ctx context.Context, val float64, set attribute.Set) {
	if set.Len() == 0 {
		m.Float64Histogram.Record(ctx, val)

		return
	}

	opts := recOptPool.Get().(*[]metric.RecordOption) // nolint: forcetypeassert

	defer func() {
		*opts = (*opts)[:0]
		recOptPool.Put(opts)
	}()

	*opts = append(*opts, metric.WithAttributeSet(set))
	m.Float64Histogram.Record(ctx, val, *opts...)
}

func (RuleExecutionDuration) AttrRuleID(val string) attribute.KeyValue   { return RuleID(val) }
func (RuleExecutionDuration) AttrRuleSet(val string) attribute.KeyValue  { return RuleSet(val) }
func (RuleExecutionDuration) AttrProvider(val string) attribute.KeyValue { return Provider(val) }
func (RuleExecutionDuration) AttrResult(val string) attribute.KeyValue   { return Result(val) }

type CertificateExpiry struct {
	metric.Float64ObservableUpDownCounter
}

var newCertificateExpiryOpts = []metric.Float64ObservableUpDownCounterOption{ //nolint:gochecknoglobals
	metric.WithDescription("Number of seconds until certificate expires"),
	metric.WithUnit("s"),
}

func NewCertificateExpiry(
	meter metric.Meter,
	opt ...metric.Float64ObservableUpDownCounterOption,
) (CertificateExpiry, error) {
	if len(opt) == 0 {
		opt = newCertificateExpiryOpts
	} else {
		opt = append(opt, newCertificateExpiryOpts...)
	}

	counter, err := meter.Float64ObservableUpDownCounter("certificate.expiry", opt...)
	if err != nil {
		return CertificateExpiry{}, err
	}

	return CertificateExpiry{counter}, nil
}

func (m CertificateExpiry) Inst() metric.Float64ObservableUpDownCounter {
	return m.Float64ObservableUpDownCounter
}

func (CertificateExpiry) Name() string {
	return "certificate.expiry"
}

func (CertificateExpiry) Unit() string {
	return "s"
}

func (CertificateExpiry) Description() string { return "Number of seconds until certificate expires" }

func (m CertificateExpiry) Observe(
	observer metric.Observer,
	value float64,
	set attribute.Set,
) {
	if set.Len() == 0 {
		observer.ObserveFloat64(m.Float64ObservableUpDownCounter, value)

		return
	}

	opts := obsOptPool.Get().(*[]metric.ObserveOption) // nolint: forcetypeassert

	defer func() {
		*opts = (*opts)[:0]
		obsOptPool.Put(opts)
	}()

	*opts = append(*opts, metric.WithAttributeSet(set))
	observer.ObserveFloat64(m.Float64ObservableUpDownCounter, value, *opts...)
}

func (CertificateExpiry) AttrService(val string) attribute.KeyValue { return CertificateService(val) }
func (CertificateExpiry) AttrIssuer(val string) attribute.KeyValue  { return CertificateIssuer(val) }
func (CertificateExpiry) AttrSubject(val string) attribute.KeyValue { return CertificateSubject(val) }
func (CertificateExpiry) AttrSerialNumber(val string) attribute.KeyValue {
	return CertificateSerialNumber(val)
}
func (CertificateExpiry) AttrDNSNames(val string) attribute.KeyValue { return CertificateDNSName(val) }

type RulesLoaded struct {
	metric.Int64ObservableGauge
}

var newRulesLoadedOpts = []metric.Int64ObservableGaugeOption{ //nolint:gochecknoglobals
	metric.WithDescription("Number of loaded rules"),
	metric.WithUnit("1"),
}

func NewRulesLoaded(
	meter metric.Meter,
	opt ...metric.Int64ObservableGaugeOption,
) (RulesLoaded, error) {
	if len(opt) == 0 {
		opt = newRulesLoadedOpts
	} else {
		opt = append(opt, newRulesLoadedOpts...)
	}

	gauge, err := meter.Int64ObservableGauge("rules.loaded", opt...)
	if err != nil {
		return RulesLoaded{}, err
	}

	return RulesLoaded{gauge}, nil
}

func (m RulesLoaded) Inst() metric.Int64ObservableGauge {
	return m.Int64ObservableGauge
}

func (RulesLoaded) Name() string {
	return "rules.loaded"
}

func (RulesLoaded) Unit() string {
	return "1"
}

func (RulesLoaded) Description() string { return "Number of loaded rules" }

func (m RulesLoaded) Observe(
	observer metric.Observer,
	value int64,
	set attribute.Set,
) {
	if set.Len() == 0 {
		observer.ObserveInt64(m.Int64ObservableGauge, value)

		return
	}

	opts := obsOptPool.Get().(*[]metric.ObserveOption) // nolint: forcetypeassert

	defer func() {
		*opts = (*opts)[:0]
		obsOptPool.Put(opts)
	}()

	*opts = append(*opts, metric.WithAttributeSet(set))
	observer.ObserveInt64(m.Int64ObservableGauge, value, *opts...)
}

func (RulesLoaded) AttrProvider(val string) attribute.KeyValue { return Provider(val) }
func (RulesLoaded) AttrRuleSet(val string) attribute.KeyValue  { return RuleSet(val) }

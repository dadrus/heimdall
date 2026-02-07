// Copyright 2025 Martin Koppehel <martin@mko.dev>
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

package contextualizers

import (
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/config"
	"github.com/dadrus/heimdall/internal/heimdall"
	heimdallmocks "github.com/dadrus/heimdall/internal/heimdall/mocks"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/identity"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/types"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/values"
	"github.com/dadrus/heimdall/internal/validation"
	"github.com/dadrus/heimdall/internal/x"
	"github.com/dadrus/heimdall/internal/x/testsupport"
)

func TestNewMapContextualizer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		enforceTLS bool
		config     []byte
		assert     func(t *testing.T, err error, contextualizer *mapContextualizer)
	}{
		"with unsupported fields": {
			config: []byte(`
values:
  url: http://foo.bar
foo: bar
`),
			assert: func(t *testing.T, err error, contextualizer *mapContextualizer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, contextualizer)
			},
		},
		"with invalid configuration": {
			config: []byte(`
items:
  method:
    foo: bar
values: 
  foo: bar
`),
			assert: func(t *testing.T, err error, _ *mapContextualizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"with minimal valid configuration": {
			enforceTLS: true,
			config: []byte(`
items:
  url: "{{ .Values.foo }}"
values: 
  foo: http://foo.bar
`),
			assert: func(t *testing.T, err error, contextualizer *mapContextualizer) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, contextualizer)

				assert.Equal(t, "with minimal valid configuration", contextualizer.ID())
				assert.Equal(t, contextualizer.Name(), contextualizer.ID())
				assert.Len(t, contextualizer.items, 1)
				assert.Len(t, contextualizer.values, 1)
				assert.Equal(t, "http://foo.bar", contextualizer.values["foo"].String())
				assert.Equal(t, "{{ .Values.foo }}", contextualizer.items["url"].String())

				vals, err := contextualizer.values.Render(map[string]any{})
				require.NoError(t, err)
				assert.Equal(t, map[string]string{"foo": "http://foo.bar"}, vals)

				val, err := contextualizer.items["url"].Render(map[string]any{
					"Values":  vals,
					"Subject": identity.Subject{"default": &identity.Principal{ID: "baz"}},
				})
				require.NoError(t, err)
				assert.Equal(t, "http://foo.bar", val)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			conf, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			es := config.EnforcementSettings{EnforceEgressTLS: tc.enforceTLS}
			validator, err := validation.NewValidator(
				validation.WithTagValidator(es),
				validation.WithErrorTranslator(es),
			)
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Maybe().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			// WHEN
			mech, err := newMapContextualizer(appCtx, uc, conf)

			// THEN
			contextualizer, ok := mech.(*mapContextualizer)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, contextualizer)
		})
	}
}

func TestMapContextualizerCreateStep(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		config  []byte
		stepDef types.StepDefinition
		assert  func(t *testing.T, err error, prototype, configured *mapContextualizer)
	}{
		"with empty target config and no step ID": {
			config: []byte(`
items:
  url: "{{ .Values.foo }}"
values: 
  foo: http://foo.bar
`),
			assert: func(t *testing.T, err error, prototype, configured *mapContextualizer) {
				t.Helper()

				require.NoError(t, err)

				assert.Equal(t, prototype, configured)
			},
		},
		"with empty target config but with step ID": {
			config: []byte(`
items:
  url: "{{ .Values.foo }}"
values: 
  foo: http://foo.bar
`),
			stepDef: types.StepDefinition{ID: "foo"},
			assert: func(t *testing.T, err error, prototype, configured *mapContextualizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, "foo", configured.ID())
			},
		},
		"with unsupported fields": {
			config: []byte(`
items:
  url: "{{ .Values.foo }}"
values: 
  foo: http://foo.bar
`),
			stepDef: types.StepDefinition{Config: config.MechanismConfig{"foo": "bar"}},
			assert: func(t *testing.T, err error, prototype, configured *mapContextualizer) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, prototype, configured)
			},
		},
		"with malformed step config": {
			config: []byte(`
items:
  url: "{{ .Values.foo }}"
values: 
  foo: http://foo.bar
`),
			stepDef: types.StepDefinition{
				Config: config.MechanismConfig{
					"values": map[string]any{"foo": 1},
				},
			},
			assert: func(t *testing.T, err error, _, _ *mapContextualizer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrConfiguration)
				require.ErrorContains(t, err, "failed decoding")
			},
		},
		"with only values reconfigured": {
			config: []byte(`
items:
  url: "{{ .Values.foo }}"
values: 
  foo: http://foo.bar
`),
			stepDef: types.StepDefinition{
				Config: config.MechanismConfig{
					"values": map[string]any{"foo": "http://bar.foo"},
				},
			},
			assert: func(t *testing.T, err error, prototype, configured *mapContextualizer) {
				t.Helper()

				require.NoError(t, err)

				assert.NotEqual(t, prototype, configured)
				assert.Equal(t, prototype.items, configured.items)
				assert.Equal(t, prototype.ID(), configured.ID())
				assert.Equal(t, prototype.Name(), configured.Name())
				assert.Equal(t, "with only values reconfigured", configured.ID())
				assert.NotEqual(t, prototype.values, configured.values)
				require.NotNil(t, configured.values)
				val, err := configured.values.Render(map[string]any{
					"Subject": identity.Subject{"default": &identity.Principal{ID: "baz"}},
				})
				require.NoError(t, err)
				resp, err := configured.items["url"].Render(map[string]any{
					"Values":  val,
					"Subject": identity.Subject{"default": &identity.Principal{ID: "baz"}},
				})
				require.NoError(t, err)
				assert.Equal(t, "http://bar.foo", resp)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			pc, err := testsupport.DecodeTestConfig(tc.config)
			require.NoError(t, err)

			validator, err := validation.NewValidator(
				validation.WithTagValidator(config.EnforcementSettings{}),
			)
			require.NoError(t, err)

			appCtx := app.NewContextMock(t)
			appCtx.EXPECT().Validator().Return(validator)
			appCtx.EXPECT().Logger().Return(log.Logger)

			mech, err := newMapContextualizer(appCtx, uc, pc)
			require.NoError(t, err)

			configured, ok := mech.(*mapContextualizer)
			require.True(t, ok)

			// WHEN
			step, err := mech.CreateStep(tc.stepDef)

			// THEN
			contextualizer, ok := step.(*mapContextualizer)
			if err == nil {
				require.True(t, ok)
			}

			tc.assert(t, err, configured, contextualizer)
		})
	}
}

func TestMapContextualizerExecute(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		contextualizer   *mapContextualizer
		subject          identity.Subject
		configureContext func(t *testing.T, ctx *heimdallmocks.ContextMock)
		assert           func(t *testing.T, err error, sub identity.Subject, outputs map[string]any)
	}{
		"with error in values rendering": {
			contextualizer: &mapContextualizer{
				id: "contextualizer1",
				values: func() values.Values {
					tpl, err := template.New("{{ len .foo }}")
					require.NoError(t, err)

					return values.Values{"foo": tpl}
				}(),
			},
			subject: identity.Subject{
				"default": &identity.Principal{
					ID:         "Foo",
					Attributes: map[string]any{"bar": "baz"},
				},
			},
			configureContext: func(t *testing.T, ctx *heimdallmocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error, _ identity.Subject, _ map[string]any) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed to render values")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "contextualizer1", identifier.ID())
			},
		},
		"with error in item rendering": {
			contextualizer: &mapContextualizer{
				id: "contextualizer1",
				values: func() values.Values {
					tpl, err := template.New("http://foo.bar")
					require.NoError(t, err)

					return values.Values{"foo": tpl}
				}(),
				items: map[string]template.Template{
					"url": func() template.Template {
						tpl, err := template.New("{{ len .foo }}")
						require.NoError(t, err)

						return tpl
					}(),
				},
			},
			subject: identity.Subject{
				"default": &identity.Principal{
					ID:         "Foo",
					Attributes: map[string]any{"bar": "baz"},
				},
			},
			configureContext: func(t *testing.T, ctx *heimdallmocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error, _ identity.Subject, _ map[string]any) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, heimdall.ErrInternal)
				require.ErrorContains(t, err, "failed to render item")

				var identifier interface{ ID() string }
				require.ErrorAs(t, err, &identifier)
				assert.Equal(t, "contextualizer1", identifier.ID())
			},
		},
		"no error": {
			contextualizer: &mapContextualizer{
				id: "contextualizer1",
				values: func() values.Values {
					tpl, err := template.New("http://foo.bar")
					require.NoError(t, err)

					return values.Values{"url": tpl}
				}(),
				items: map[string]template.Template{
					"urlValues": func() template.Template {
						tpl, err := template.New("{{ .Values.url }}")
						require.NoError(t, err)

						return tpl
					}(),
					"identity": func() template.Template {
						tpl, err := template.New("{{ .Subject.ID }}")
						require.NoError(t, err)

						return tpl
					}(),
					"outputs": func() template.Template {
						tpl, err := template.New("{{ .Outputs.foo }}")
						require.NoError(t, err)

						return tpl
					}(),
				},
			},
			subject: identity.Subject{
				"default": &identity.Principal{
					ID:         "Foo",
					Attributes: map[string]any{"bar": "baz"},
				},
			},
			configureContext: func(t *testing.T, ctx *heimdallmocks.ContextMock) {
				t.Helper()

				ctx.EXPECT().Request().Return(nil)
			},
			assert: func(t *testing.T, err error, _ identity.Subject, outputs map[string]any) {
				t.Helper()

				require.NoError(t, err)

				assert.NotNil(t, outputs["contextualizer1"])
				assert.Equal(t, "http://foo.bar", outputs["contextualizer1"].(map[string]string)["urlValues"])
				assert.Equal(t, "Foo", outputs["contextualizer1"].(map[string]string)["identity"])
				assert.Equal(t, "bar", outputs["contextualizer1"].(map[string]string)["outputs"])
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			configureContext := x.IfThenElse(tc.configureContext != nil,
				tc.configureContext,
				func(t *testing.T, _ *heimdallmocks.ContextMock) { t.Helper() })

			ctx := heimdallmocks.NewContextMock(t)
			ctx.EXPECT().Outputs().Return(map[string]any{"foo": "bar"})
			ctx.EXPECT().Context().Return(t.Context())

			configureContext(t, ctx)

			// WHEN
			err := tc.contextualizer.Execute(ctx, tc.subject)

			// THEN
			tc.assert(t, err, tc.subject, ctx.Outputs())
		})
	}
}

func TestMapContextualizerAccept(t *testing.T) {
	t.Parallel()

	mech := &mapContextualizer{}

	mech.Accept(nil)
}

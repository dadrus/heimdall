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

package source

import (
	"context"
	"slices"

	"github.com/dadrus/heimdall/internal/secrets/provider"
	"github.com/dadrus/heimdall/internal/secrets/types"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type secretsResolver struct {
	name string
	deps []types.Reference
	r    provider.DependenciesResolver
}

func (r *secretsResolver) ResolveSecret(
	ctx context.Context,
	ref types.Reference,
) (types.Secret, error) {
	if err := r.checkReference(ref); err != nil {
		return nil, err
	}

	return r.r.ResolveSecret(ctx, ref)
}

func (r *secretsResolver) ResolveCredentials(
	ctx context.Context,
	ref types.Reference,
) (types.Credentials, error) {
	if err := r.checkReference(ref); err != nil {
		return nil, err
	}

	return r.r.ResolveCredentials(ctx, ref)
}

func (r *secretsResolver) ResolveCertificateBundle(
	ctx context.Context,
	ref types.Reference,
) (types.CertificateBundle, error) {
	if err := r.checkReference(ref); err != nil {
		return nil, err
	}

	return r.r.ResolveCertificateBundle(ctx, ref)
}

func (r *secretsResolver) checkReference(ref types.Reference) error {
	if !slices.ContainsFunc(r.deps, func(dep types.Reference) bool {
		return dep.Source == ref.Source && dep.Selector == ref.Selector
	}) {
		return errorchain.NewWithMessagef(
			types.ErrDependencyNotDeclared,
			"secret reference '%s/%s' is not a declared dependency of secret source '%s'",
			ref.Source,
			ref.Selector,
			r.name,
		)
	}

	return nil
}

func (r *secretsResolver) dependsOn(evt Event) bool {
	for _, dep := range r.deps {
		if dep.Source != evt.Source {
			continue
		}

		if len(evt.Selectors) == 0 {
			return true
		}

		for _, selector := range evt.Selectors {
			if dep.Selector == selector.Value {
				return true
			}
		}
	}

	return false
}

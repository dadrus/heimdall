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

package rules

import (
	"slices"
	"strings"

	"github.com/rs/zerolog"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/identity"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type stepVisitor struct {
	insecure   []bool
	principals []string
}

func (v *stepVisitor) VisitInsecure(obj heimdall.Insecure) {
	v.insecure = append(v.insecure, obj.IsInsecure())
}

func (v *stepVisitor) VisitPrincipalNamer(obj heimdall.PrincipalNamer) {
	v.principals = append(v.principals, obj.PrincipalName())
}

type step interface {
	Accept(visitor heimdall.Visitor)
	Execute(ctx heimdall.Context, sub identity.Subject) error
}

type stage []step

func (s stage) HasDefaultPrincipal() bool {
	sv := &stepVisitor{}

	for _, step := range s {
		step.Accept(sv)
	}

	return slices.Contains(sv.principals, "default")
}

func (s stage) IsInsecure() bool {
	if len(s) == 0 {
		return false
	}

	sv := &stepVisitor{}
	s[0].Accept(sv)

	if len(sv.insecure) == 0 {
		return false
	}

	return sv.insecure[0]
}

func (s stage) Execute(ctx heimdall.Context, sub identity.Subject) error {
	logger := zerolog.Ctx(ctx.Context())

	for _, step := range s {
		err := step.Execute(ctx, sub)
		if err != nil {
			logger.Info().Err(err).Msg("Pipeline step execution failed")

			if strings.Contains(err.Error(), "tls:") {
				return errorchain.New(heimdall.ErrInternal).CausedBy(err)
			}

			return err
		}
	}

	return nil
}

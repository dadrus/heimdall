// Copyright 2022-2025 Dimitrij Drus <dadrus@gmx.de>
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

package serve

import (
	"strings"

	"github.com/rs/zerolog"
	"go.uber.org/fx/fxevent"
)

type eventLogger struct {
	l zerolog.Logger
}

func (l *eventLogger) LogEvent(event fxevent.Event) { //nolint:gocognit, gocyclo, cyclop, funlen, maintidx
	switch evt := event.(type) {
	case *fxevent.OnStartExecuting:
		l.l.Trace().
			Str("_functionName", evt.FunctionName).
			Str("_caller", evt.CallerName).
			Msg("OnStart hook executing")
	case *fxevent.OnStartExecuted:
		if evt.Err != nil {
			l.l.Error().
				Err(evt.Err).
				Str("_functionName", evt.FunctionName).
				Str("_caller", evt.CallerName).
				Msg("OnStart hook failed")
		} else {
			l.l.Trace().
				Str("_functionName", evt.FunctionName).
				Str("_caller", evt.CallerName).
				Str("_runtime", evt.Runtime.String()).
				Msg("OnStart hook executed")
		}
	case *fxevent.OnStopExecuting:
		l.l.Trace().
			Str("_functionName", evt.FunctionName).
			Str("_caller", evt.CallerName).
			Msg("OnStop hook executing")
	case *fxevent.OnStopExecuted:
		if evt.Err != nil {
			l.l.Error().
				Err(evt.Err).
				Str("_functionName", evt.FunctionName).
				Str("_caller", evt.CallerName).
				Msg("OnStop hook failed")
		} else {
			l.l.Trace().
				Str("_functionName", evt.FunctionName).
				Str("_caller", evt.CallerName).
				Str("_runtime", evt.Runtime.String()).
				Msg("OnStop hook executed")
		}
	case *fxevent.Supplied:
		if evt.Err != nil {
			l.l.Error().
				Err(evt.Err).
				Str("_type", evt.TypeName).
				Str("_module", evt.ModuleName).
				Strs("_stacktrace", evt.StackTrace).
				Strs("_moduleTrace", evt.ModuleTrace).
				Msg("Error encountered while supplying module")
		} else {
			l.l.Trace().
				Str("_type", evt.TypeName).
				Str("_module", evt.ModuleName).
				Strs("_moduleTrace", evt.ModuleTrace).
				Msg("Module supplied")
		}
	case *fxevent.Provided:
		if evt.Err == nil {
			for _, rtype := range evt.OutputTypeNames {
				l.l.Trace().
					Str("_type", rtype).
					Str("_module", evt.ModuleName).
					Str("_constructor", evt.ConstructorName).
					Bool("_private", evt.Private).
					Strs("_stacktrace", evt.StackTrace).
					Strs("_moduleTrace", evt.ModuleTrace).
					Msg("Module provided")
			}
		} else {
			l.l.Error().
				Err(evt.Err).
				Str("_module", evt.ModuleName).
				Strs("_stacktrace", evt.StackTrace).
				Strs("_moduleTrace", evt.ModuleTrace).
				Msg("Error encountered while providing module")
		}
	case *fxevent.Replaced:
		if evt.Err == nil {
			for _, rtype := range evt.OutputTypeNames {
				l.l.Trace().
					Str("_type", rtype).
					Str("_module", evt.ModuleName).
					Strs("_stacktrace", evt.StackTrace).
					Strs("_moduleTrace", evt.ModuleTrace).
					Msg("Module replaced")
			}
		} else {
			l.l.Error().
				Err(evt.Err).
				Str("_module", evt.ModuleName).
				Strs("_stacktrace", evt.StackTrace).
				Strs("_moduleTrace", evt.ModuleTrace).
				Msg("Error encountered while replacing module")
		}
	case *fxevent.Decorated:
		if evt.Err == nil {
			for _, rtype := range evt.OutputTypeNames {
				l.l.Trace().
					Str("_type", rtype).
					Str("_module", evt.ModuleName).
					Str("_decorator", evt.DecoratorName).
					Strs("_stacktrace", evt.StackTrace).
					Strs("_moduleTrace", evt.ModuleTrace).
					Msg("Module decorated")
			}
		} else {
			l.l.Error().
				Err(evt.Err).
				Str("_module", evt.ModuleName).
				Strs("_stacktrace", evt.StackTrace).
				Strs("_moduleTrace", evt.ModuleTrace).
				Msg("Error encountered while decorating module")
		}
	case *fxevent.Run:
		if evt.Err != nil {
			l.l.Error().
				Err(evt.Err).
				Str("_module", evt.ModuleName).
				Str("_name", evt.Name).
				Str("_kind", evt.Kind).
				Msg("Error returned")
		} else {
			l.l.Trace().
				Str("_name", evt.Name).
				Str("_module", evt.ModuleName).
				Str("_kind", evt.Kind).
				Str("_runtime", evt.Runtime.String()).
				Msg("Starting")
		}
	case *fxevent.Invoking:
		l.l.Trace().
			Str("_module", evt.ModuleName).
			Str("_function", evt.FunctionName).
			Msg("Invoking module")
	case *fxevent.Invoked:
		if evt.Err != nil {
			l.l.Error().
				Err(evt.Err).
				Str("_module", evt.ModuleName).
				Str("_function", evt.FunctionName).
				Str("_stack", evt.Trace).
				Msg("Invoke failed")
		} else {
			l.l.Trace().
				Str("_module", evt.ModuleName).
				Str("_function", evt.FunctionName).
				Str("_stack", evt.Trace).
				Msg("Invoked module")
		}
	case *fxevent.Stopping:
		l.l.Trace().
			Str("_signal", strings.ToUpper(evt.Signal.String())).
			Msg("Received signal")
	case *fxevent.Stopped:
		if evt.Err != nil {
			l.l.Error().
				Err(evt.Err).
				Msg("Stop failed")
		} else {
			l.l.Trace().
				Msg("Stopped")
		}
	case *fxevent.RollingBack:
		l.l.Error().
			Err(evt.StartErr).
			Msg("Start failed, rolling back")
	case *fxevent.RolledBack:
		if evt.Err != nil {
			l.l.Error().
				Err(evt.Err).
				Msg("Rollback failed")
		} else {
			l.l.Trace().
				Msg("Rollback succeeded")
		}
	case *fxevent.Started:
		if evt.Err != nil {
			l.l.Error().
				Err(evt.Err).
				Msg("Start failed")
		} else {
			l.l.Trace().
				Msg("Started")
		}
	case *fxevent.LoggerInitialized:
		if evt.Err != nil {
			l.l.Error().
				Err(evt.Err).
				Msg("Custom logger initialization failed")
		}
	}
}

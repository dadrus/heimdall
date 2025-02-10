package serve

import (
	"strings"

	"github.com/rs/zerolog"
	"go.uber.org/fx/fxevent"
)

type eventLogger struct {
	l zerolog.Logger
}

func (l *eventLogger) LogEvent(event fxevent.Event) { //nolint:gocognit
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

		if evt.Err != nil {
			l.l.Error().
				Err(evt.Err).
				Str("_module", evt.ModuleName).
				Strs("_stacktrace", evt.StackTrace).
				Strs("_moduleTrace", evt.ModuleTrace).
				Msg("Error encountered while providing module")
		}
	case *fxevent.Replaced:
		for _, rtype := range evt.OutputTypeNames {
			l.l.Trace().
				Str("_type", rtype).
				Str("_module", evt.ModuleName).
				Strs("_stacktrace", evt.StackTrace).
				Strs("_moduleTrace", evt.ModuleTrace).
				Msg("Module replaced")
		}

		if evt.Err != nil {
			l.l.Error().
				Err(evt.Err).
				Str("_module", evt.ModuleName).
				Strs("_stacktrace", evt.StackTrace).
				Strs("_moduleTrace", evt.ModuleTrace).
				Msg("Error encountered while replacing module")
		}
	case *fxevent.Decorated:
		for _, rtype := range evt.OutputTypeNames {
			l.l.Trace().
				Str("_type", rtype).
				Str("_module", evt.ModuleName).
				Str("_decorator", evt.DecoratorName).
				Strs("_stacktrace", evt.StackTrace).
				Strs("_moduleTrace", evt.ModuleTrace).
				Msg("Module decorated")
		}

		if evt.Err != nil {
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

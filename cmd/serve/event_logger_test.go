package serve

import (
	"bytes"
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"go.uber.org/fx/fxevent"
)

func TestFxlogger(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		evt    fxevent.Event
		expMsg string
	}{
		"OnStartExecuting": {
			evt: &fxevent.OnStartExecuting{
				FunctionName: "testFunction",
				CallerName:   "TestCaller",
			},
			expMsg: `{"level": "trace", "_functionName": "testFunction", "_caller": "TestCaller", "message": "OnStart hook executing"}`,
		},
		"OnStartExecuted with error": {
			evt: &fxevent.OnStartExecuted{
				FunctionName: "testFunction",
				CallerName:   "TestCaller",
				Err:          errors.New("test error"),
				Runtime:      1 * time.Second,
			},
			expMsg: `{"level":"error", "_caller":"TestCaller", "_functionName":"testFunction", "error":"test error", "message":"OnStart hook failed"}`,
		},
		"OnStartExecuted without error": {
			evt: &fxevent.OnStartExecuted{
				FunctionName: "testFunction",
				CallerName:   "TestCaller",
				Runtime:      1 * time.Second,
			},
			expMsg: `{"_caller":"TestCaller", "_functionName":"testFunction", "_runtime":"1s", "level":"trace", "message":"OnStart hook executed"}`,
		},
		"OnStopExecuting": {
			evt: &fxevent.OnStopExecuting{
				FunctionName: "testFunction",
				CallerName:   "TestCaller",
			},
			expMsg: `{"_caller":"TestCaller", "_functionName":"testFunction", "level":"trace", "message":"OnStop hook executing"}`,
		},
		"OnStopExecuted with error": {
			evt: &fxevent.OnStopExecuted{
				FunctionName: "testFunction",
				CallerName:   "TestCaller",
				Err:          errors.New("test error"),
				Runtime:      1 * time.Second,
			},
			expMsg: `{"_caller":"TestCaller", "_functionName":"testFunction", "error":"test error", "level":"error", "message":"OnStop hook failed"}`,
		},
		"OnStopExecuted without error": {
			evt: &fxevent.OnStopExecuted{
				FunctionName: "testFunction",
				CallerName:   "TestCaller",
				Runtime:      1 * time.Second,
			},
			expMsg: `{"_caller":"TestCaller", "_functionName":"testFunction", "_runtime":"1s", "level":"trace", "message":"OnStop hook executed"}`,
		},
		"Supplied with error": {
			evt: &fxevent.Supplied{
				TypeName:    "testType",
				StackTrace:  []string{"TestStackTrace"},
				ModuleTrace: []string{"TestModuleTrace"},
				ModuleName:  "testModule",
				Err:         errors.New("test error"),
			},
			expMsg: `{"_module":"testModule", "_moduleTrace":["TestModuleTrace"], "_stacktrace":["TestStackTrace"], "_type":"testType", "error":"test error", "level":"error", "message":"Error encountered while supplying module"}`,
		},
		"Supplied without error": {
			evt: &fxevent.Supplied{
				TypeName:    "testType",
				ModuleTrace: []string{"TestModuleTrace"},
				ModuleName:  "testModule",
			},
			expMsg: `{"_module":"testModule", "_moduleTrace":["TestModuleTrace"], "_type":"testType", "level":"trace", "message":"Module supplied"}`,
		},
		"Provided with error": {
			evt: &fxevent.Provided{
				OutputTypeNames: []string{"testType"},
				ConstructorName: "testConstructor",
				StackTrace:      []string{"TestStackTrace"},
				ModuleTrace:     []string{"TestModuleTrace"},
				ModuleName:      "testModule",
				Err:             errors.New("test error"),
				Private:         false,
			},
			expMsg: `{"_module":"testModule", "_moduleTrace":["TestModuleTrace"], "_stacktrace":["TestStackTrace"], "error":"test error", "level":"error", "message":"Error encountered while providing module"}`,
		},
		"Provided without error": {
			evt: &fxevent.Provided{
				OutputTypeNames: []string{"testType"},
				ConstructorName: "testConstructor",
				ModuleTrace:     []string{"TestModuleTrace"},
				ModuleName:      "testModule",
				Private:         false,
			},
			expMsg: `{"_constructor":"testConstructor", "_module":"testModule", "_moduleTrace":["TestModuleTrace"], "_private":false, "_stacktrace":[], "_type":"testType", "level":"trace", "message":"Module provided"}`,
		},
		"Replaced with error": {
			evt: &fxevent.Replaced{
				OutputTypeNames: []string{"testType"},
				StackTrace:      []string{"TestStackTrace"},
				ModuleTrace:     []string{"TestModuleTrace"},
				ModuleName:      "testModule",
				Err:             errors.New("test error"),
			},
			expMsg: `{"_module":"testModule", "_moduleTrace":["TestModuleTrace"], "_stacktrace":["TestStackTrace"], "error":"test error", "level":"error", "message":"Error encountered while replacing module"}`,
		},
		"Replaced without error": {
			evt: &fxevent.Replaced{
				OutputTypeNames: []string{"testType"},
				ModuleTrace:     []string{"TestModuleTrace"},
				ModuleName:      "testModule",
			},
			expMsg: `{"_module":"testModule", "_moduleTrace":["TestModuleTrace"], "_stacktrace":[], "_type":"testType", "level":"trace", "message":"Module replaced"}`,
		},
		"Decorated with error": {
			evt: &fxevent.Decorated{
				DecoratorName:   "testDecorator",
				OutputTypeNames: []string{"testType"},
				StackTrace:      []string{"TestStackTrace"},
				ModuleTrace:     []string{"TestModuleTrace"},
				ModuleName:      "testModule",
				Err:             errors.New("test error"),
			},
			expMsg: `{"_module":"testModule", "_moduleTrace":["TestModuleTrace"], "_stacktrace":["TestStackTrace"], "error":"test error", "level":"error", "message":"Error encountered while decorating module"}`,
		},
		"Decorated without error": {
			evt: &fxevent.Decorated{
				DecoratorName:   "testDecorator",
				OutputTypeNames: []string{"testType"},
				ModuleTrace:     []string{"TestModuleTrace"},
				ModuleName:      "testModule",
			},
			expMsg: `{"_decorator":"testDecorator", "_module":"testModule", "_moduleTrace":["TestModuleTrace"], "_stacktrace":[], "_type":"testType", "level":"trace", "message":"Module decorated"}`,
		},
		"Run with error": {
			evt: &fxevent.Run{
				Name:       "testName",
				Kind:       "testKind",
				ModuleName: "testModule",
				Runtime:    1 * time.Second,
				Err:        errors.New("test error"),
			},
			expMsg: `{"_kind":"testKind", "_module":"testModule", "_name":"testName", "error":"test error", "level":"error", "message":"Error returned"}`,
		},
		"Run without error": {
			evt: &fxevent.Run{
				Name:       "testName",
				Kind:       "testKind",
				ModuleName: "testModule",
				Runtime:    1 * time.Second,
			},
			expMsg: `{"_kind":"testKind", "_module":"testModule", "_name":"testName", "_runtime":"1s", "level":"trace", "message":"Starting"}`,
		},
		"Invoking": {
			evt: &fxevent.Invoking{
				FunctionName: "testFunction",
				ModuleName:   "testModule",
			},
			expMsg: `{"_function":"testFunction", "_module":"testModule", "level":"trace", "message":"Invoking module"}`,
		},
		"Invoked with error": {
			evt: &fxevent.Invoked{
				FunctionName: "testFunction",
				ModuleName:   "testModule",
				Err:          errors.New("test error"),
				Trace:        "TestTrace",
			},
			expMsg: `{"_function":"testFunction", "_module":"testModule", "_stack":"TestTrace", "error":"test error", "level":"error", "message":"Invoke failed"}`,
		},
		"Invoked without error": {
			evt: &fxevent.Invoked{
				FunctionName: "testFunction",
				ModuleName:   "testModule",
				Trace:        "TestTrace",
			},
			expMsg: `{"_function":"testFunction", "_module":"testModule", "_stack":"TestTrace", "level":"trace", "message":"Invoked module"}`,
		},
		"Stopping": {
			evt: &fxevent.Stopping{
				Signal: syscall.SIGINT,
			},
			expMsg: `{"_signal":"INTERRUPT", "level":"trace", "message":"Received signal"}`,
		},
		"Stopped with error": {
			evt: &fxevent.Stopped{
				Err: errors.New("test error"),
			},
			expMsg: `{"error":"test error", "level":"error", "message":"Stop failed"}`,
		},
		"Stopped without error": {
			evt:    &fxevent.Stopped{},
			expMsg: `{"level":"trace", "message":"Stopped"}`,
		},
		"RollingBack": {
			evt: &fxevent.RollingBack{
				StartErr: errors.New("test error"),
			},
			expMsg: `{"error":"test error", "level":"error", "message":"Start failed, rolling back"}`,
		},
		"RolledBack with error": {
			evt: &fxevent.RolledBack{
				Err: errors.New("test error"),
			},
			expMsg: `{"error":"test error", "level":"error", "message":"Rollback failed"}`,
		},
		"RolledBack without error": {
			evt:    &fxevent.RolledBack{},
			expMsg: `{"level":"trace", "message":"Rollback succeeded"}`,
		},
		"Started with error": {
			evt: &fxevent.Started{
				Err: errors.New("test error"),
			},
			expMsg: `{"error":"test error", "level":"error", "message":"Start failed"}`,
		},
		"Started without error": {
			evt:    &fxevent.Started{},
			expMsg: `{"level":"trace", "message":"Started"}`,
		},
		"LoggerInitialized with error": {
			evt: &fxevent.LoggerInitialized{
				Err:             errors.New("test error"),
				ConstructorName: "testConstructor",
			},
			expMsg: `{"error":"test error", "level":"error", "message":"Custom logger initialization failed"}`,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			buf := bytes.NewBufferString("")
			evtLogger := &eventLogger{l: zerolog.New(buf)}
			evtLogger.LogEvent(tc.evt)

			assert.JSONEq(t, tc.expMsg, buf.String())
		})
	}
}

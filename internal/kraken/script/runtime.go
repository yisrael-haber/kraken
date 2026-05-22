package script

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	starlarkjson "go.starlark.net/lib/json"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"
)

const (
	entryPointName               = "main"
	storedScriptCompileStepLimit = 5_000_000
	storedScriptCompileTimeout   = time.Second
)

var scriptFileOptions = &syntax.FileOptions{
	While:           true,
	TopLevelControl: true,
	GlobalReassign:  true,
}

type runtimeLoad func(*starlark.Thread, string) (starlark.StringDict, error)

var (
	errScriptCompileTimedOut = errors.New("script validation timed out")
	sharedBytesModule        = buildBytesModule()
	sharedStructBuiltin      = starlark.NewBuiltin("struct", starlarkstruct.Make)
	sharedExecRuntime        = newRuntimeLoad(buildTimeModule(true), buildLogModule(nil))
	sharedCompileRuntime     = newRuntimeLoad(buildTimeModule(false), buildLogModule(nil))
)

func MissingStoredScriptError(name string) error {
	return fmt.Errorf("stored script %q was not found", strings.TrimSpace(name))
}

func ExecuteTransport(compiled *CompiledScript, packet *MutablePacket, ctx ExecutionContext, logf LogFunc) error {
	if err := validateExecutableScript(compiled, SurfaceTransport); err != nil {
		return err
	}

	ctxValue, err := newContextValue(ctx)
	if err != nil {
		return err
	}

	thread := newRuntimeThread(compiled.name, runtimeFor(true, logf), logf)
	globals, err := compiled.program.Init(thread, starlark.StringDict{})
	if err != nil {
		return normalizeRuntimeError(err)
	}

	mainValue := globals[entryPointName]
	callable, ok := mainValue.(starlark.Callable)
	if !ok {
		return fmt.Errorf("script %q does not expose %q", compiled.name, entryPointName)
	}

	if _, err := starlark.Call(thread, callable, starlark.Tuple{packet, ctxValue}, nil); err != nil {
		return normalizeRuntimeError(err)
	}

	return packet.finalize()
}

func validateExecutableScript(compiled *CompiledScript, surface Surface) error {
	if compiled == nil || compiled.program == nil {
		return fmt.Errorf("script is invalid: script is unavailable")
	}
	if compiled.surface != surface {
		return fmt.Errorf("script %q uses %q surface, expected %q", compiled.name, compiled.surface, surface)
	}
	return nil
}

func Compile(name string, surface Surface, source string) (*CompiledScript, error) {
	predeclared := starlark.StringDict{}
	_, program, err := starlark.SourceProgramOptions(scriptFileOptions, name, source, predeclared.Has)
	if err != nil {
		return nil, err
	}

	thread := newRuntimeThread(name, runtimeFor(false, nil), nil)
	thread.SetMaxExecutionSteps(storedScriptCompileStepLimit)
	thread.OnMaxSteps = func(thread *starlark.Thread) {
		thread.Cancel(errScriptCompileTimedOut.Error())
	}

	timer := time.AfterFunc(storedScriptCompileTimeout, func() {
		thread.Cancel(errScriptCompileTimedOut.Error())
	})
	defer timer.Stop()

	globals, err := program.Init(thread, predeclared)
	if err != nil {
		if strings.Contains(err.Error(), errScriptCompileTimedOut.Error()) {
			return nil, fmt.Errorf("%w after %s", errScriptCompileTimedOut, storedScriptCompileTimeout)
		}
		return nil, err
	}
	if err := validateCompiledScriptSurface(name, surface, globals); err != nil {
		return nil, err
	}

	return &CompiledScript{name: name, surface: surface, program: program}, nil
}

func validateCompiledScriptSurface(name string, surface Surface, globals starlark.StringDict) error {
	switch surface {
	case SurfaceTransport, SurfaceApplication:
		if _, ok := globals[entryPointName].(starlark.Callable); !ok {
			return fmt.Errorf("%s must define a %q function", name, entryPointName)
		}
	default:
		return fmt.Errorf("unsupported script surface %q", surface)
	}

	return nil
}

func runtimeFor(allowSleep bool, logf LogFunc) runtimeLoad {
	if logf != nil {
		return newRuntimeLoad(buildTimeModule(allowSleep), buildLogModule(logf))
	}
	if allowSleep {
		return sharedExecRuntime
	}
	return sharedCompileRuntime
}

func newRuntimeLoad(timeModule starlark.Value, logModule starlark.Value) runtimeLoad {
	loads := map[string]starlark.StringDict{
		"kraken/bytes": {"bytes": sharedBytesModule},
		"kraken/time":  {"time": timeModule},
		"kraken/log":   {"log": logModule},
		"json":         {"json": starlarkjson.Module},
		"struct":       {"struct": sharedStructBuiltin},
	}
	return func(_ *starlark.Thread, module string) (starlark.StringDict, error) {
		globals, exists := loads[module]
		if !exists {
			return nil, fmt.Errorf("unsupported module %q", module)
		}
		return globals, nil
	}
}

func newRuntimeThread(name string, load runtimeLoad, logf LogFunc) *starlark.Thread {
	return &starlark.Thread{
		Name: name,
		Load: load,
		Print: func(_ *starlark.Thread, message string) {
			if logf != nil {
				logf("info", message)
			}
		},
	}
}

func buildTimeModule(allowSleep bool) starlark.Value {
	sleepBuiltin := starlark.NewBuiltin("time.sleep", func(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if !allowSleep {
			return nil, fmt.Errorf("kraken/time.sleep is unavailable during validation")
		}

		var durationValue starlark.Value
		if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &durationValue); err != nil {
			return nil, err
		}

		switch value := durationValue.(type) {
		case starlark.Int:
			var milliseconds int64
			if err := starlark.AsInt(value, &milliseconds); err != nil {
				return nil, err
			}
			if milliseconds < 0 {
				return nil, fmt.Errorf("kraken/time.sleep requires a non-negative millisecond duration")
			}
			time.Sleep(time.Duration(milliseconds) * time.Millisecond)
		case starlark.Float:
			if math.IsNaN(float64(value)) || value < 0 {
				return nil, fmt.Errorf("kraken/time.sleep requires a non-negative millisecond duration")
			}
			time.Sleep(time.Duration(float64(value) * float64(time.Millisecond)))
		default:
			return nil, fmt.Errorf("kraken/time.sleep requires a numeric millisecond duration")
		}

		return starlark.None, nil
	})

	module := &starlarkstruct.Module{
		Name: "kraken/time",
		Members: starlark.StringDict{
			"nowMs": starlark.NewBuiltin("time.nowMs", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				if err := starlark.UnpackPositionalArgs("time.nowMs", args, kwargs, 0); err != nil {
					return nil, err
				}
				return starlark.MakeInt64(time.Now().UnixMilli()), nil
			}),
			"sleep": sleepBuiltin,
		},
	}

	return module
}

func buildLogModule(logf LogFunc) starlark.Value {
	module := &starlarkstruct.Module{
		Name:    "kraken/log",
		Members: starlark.StringDict{},
	}

	for _, level := range []string{"info", "warn", "error"} {
		levelName := level
		module.Members[levelName] = starlark.NewBuiltin("log."+levelName, func(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var message starlark.Value
			if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &message); err != nil {
				return nil, err
			}
			if logf != nil {
				if text, ok := starlark.AsString(message); ok {
					logf(levelName, text)
				} else {
					logf(levelName, message.String())
				}
			}
			return starlark.None, nil
		})
	}

	return module
}

func normalizeRuntimeError(err error) error {
	var evalErr *starlark.EvalError
	if errors.As(err, &evalErr) {
		return fmt.Errorf("%s", strings.TrimSpace(evalErr.Backtrace()))
	}
	return err
}

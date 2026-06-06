package script

import (
	"errors"
	"fmt"
	"strings"
	"time"

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
	sharedExecRuntime        = newRuntimeLoad(buildTimeModule(true))
	sharedCompileRuntime     = newRuntimeLoad(buildTimeModule(false))
)

func MissingStoredScriptError(name string) error {
	return fmt.Errorf("stored script %q was not found", strings.TrimSpace(name))
}

func ExecuteTransport(compiled *CompiledScript, frame []byte, ctx ExecutionContext) ([]byte, error) {
	if compiled == nil || compiled.program == nil {
		return nil, fmt.Errorf("script is invalid: script is unavailable")
	}
	if compiled.surface != SurfaceTransport {
		return nil, fmt.Errorf("script %q uses %q surface, expected %q", compiled.name, compiled.surface, SurfaceTransport)
	}

	packet, err := newMutablePacket(frame)
	if err != nil {
		return nil, err
	}

	ctxValue := newContextValue(ctx)

	thread := &starlark.Thread{
		Name: compiled.name,
		Load: sharedExecRuntime,
	}
	globals, err := compiled.program.Init(thread, starlark.StringDict{})
	if err != nil {
		return nil, normalizeRuntimeError(err)
	}

	callable, ok := globals[entryPointName].(starlark.Callable)
	if !ok {
		return nil, fmt.Errorf("script %q does not expose %q", compiled.name, entryPointName)
	}

	if _, err := starlark.Call(thread, callable, starlark.Tuple{packet, ctxValue}, nil); err != nil {
		return nil, normalizeRuntimeError(err)
	}

	return packet.finalize(frame)
}

func Compile(name string, surface Surface, source string) (*CompiledScript, error) {
	if surface != SurfaceTransport && surface != SurfaceApplication {
		return nil, fmt.Errorf("unsupported script surface %q", surface)
	}

	_, program, err := starlark.SourceProgramOptions(scriptFileOptions, name, source, starlark.StringDict(nil).Has)
	if err != nil {
		return nil, err
	}

	thread := &starlark.Thread{Name: name, Load: sharedCompileRuntime}
	thread.SetMaxExecutionSteps(storedScriptCompileStepLimit)
	thread.OnMaxSteps = func(thread *starlark.Thread) {
		thread.Cancel(errScriptCompileTimedOut.Error())
	}

	timer := time.AfterFunc(storedScriptCompileTimeout, func() {
		thread.Cancel(errScriptCompileTimedOut.Error())
	})
	defer timer.Stop()

	globals, err := program.Init(thread, starlark.StringDict{})
	if err != nil {
		if strings.Contains(err.Error(), errScriptCompileTimedOut.Error()) {
			return nil, fmt.Errorf("%w after %s", errScriptCompileTimedOut, storedScriptCompileTimeout)
		}
		return nil, err
	}
	if _, ok := globals[entryPointName].(starlark.Callable); !ok {
		return nil, fmt.Errorf("%s must define a %q function", name, entryPointName)
	}

	return &CompiledScript{name: name, surface: surface, program: program}, nil
}

func newRuntimeLoad(timeModule starlark.Value) runtimeLoad {
	loads := map[string]starlark.StringDict{
		"kraken/bytes": {"bytes": sharedBytesModule},
		"kraken/time":  {"time": timeModule},
	}
	return func(_ *starlark.Thread, module string) (starlark.StringDict, error) {
		globals, exists := loads[module]
		if !exists {
			return nil, fmt.Errorf("unsupported module %q", module)
		}
		return globals, nil
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

		number, ok := durationValue.(starlark.Int)
		if !ok {
			return nil, fmt.Errorf("kraken/time.sleep requires an integer millisecond duration")
		}
		var milliseconds int64
		if err := starlark.AsInt(number, &milliseconds); err != nil {
			return nil, err
		}
		if milliseconds < 0 {
			return nil, fmt.Errorf("kraken/time.sleep requires a non-negative millisecond duration")
		}
		time.Sleep(time.Duration(milliseconds) * time.Millisecond)
		return starlark.None, nil
	})

	return &starlarkstruct.Module{
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
}

func normalizeRuntimeError(err error) error {
	var evalErr *starlark.EvalError
	if errors.As(err, &evalErr) {
		return fmt.Errorf("%s", strings.TrimSpace(evalErr.Backtrace()))
	}
	return err
}

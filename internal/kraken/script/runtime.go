package script

import (
	"bytes"
	"context"
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
)

func MissingStoredScriptError(name string) error {
	return fmt.Errorf("stored script %q was not found", strings.TrimSpace(name))
}

type RunResult struct {
	Stdout string `json:"stdout,omitempty"`
	Stderr string `json:"stderr,omitempty"`
	Output string `json:"output,omitempty"`
}

func ExecuteTransport(compiled *CompiledScript, frame []byte, ctx ExecutionContext, send func([]byte) error) error {
	if compiled == nil || compiled.program == nil {
		return fmt.Errorf("script is invalid: script is unavailable")
	}
	if compiled.kind != "" && compiled.kind != ScriptKindTransport {
		return fmt.Errorf("script %q is not a transport script", compiled.name)
	}
	packet, err := newMutablePacket(frame, send)
	if err != nil {
		return err
	}

	ctxValue := newContextValue(ctx)

	thread := &starlark.Thread{
		Name: compiled.name,
		Load: newRuntimeLoad(ctx, true),
	}
	globals, err := compiled.program.Init(thread, starlark.StringDict{})
	if err != nil {
		return normalizeRuntimeError(err)
	}

	callable, ok := globals[entryPointName].(starlark.Callable)
	if !ok {
		return fmt.Errorf("script %q does not expose %q", compiled.name, entryPointName)
	}

	if _, err := starlark.Call(thread, callable, starlark.Tuple{packet, ctxValue}, nil); err != nil {
		return normalizeRuntimeError(err)
	}

	return nil
}

func ExecuteGeneric(compiled *CompiledScript, ctx ExecutionContext) (RunResult, error) {
	return ExecuteGenericWithContext(context.Background(), compiled, ctx)
}

func ExecuteGenericWithContext(runContext context.Context, compiled *CompiledScript, ctx ExecutionContext) (RunResult, error) {
	if compiled == nil || compiled.program == nil {
		return RunResult{}, fmt.Errorf("script is invalid: script is unavailable")
	}
	if compiled.kind != ScriptKindGeneric {
		return RunResult{}, fmt.Errorf("script %q is not a generic script", compiled.name)
	}
	if runContext == nil {
		runContext = context.Background()
	}
	ctx.RunContext = runContext

	ctxValue := newContextValue(ctx)
	var output bytes.Buffer
	thread := &starlark.Thread{
		Name: compiled.name,
		Load: newRuntimeLoad(ctx, true),
		Print: func(_ *starlark.Thread, msg string) {
			line := msg + "\n"
			output.WriteString(line)
			if ctx.Stdout != nil {
				ctx.Stdout(line)
			}
		},
	}
	cancelDone := make(chan struct{})
	go func() {
		select {
		case <-runContext.Done():
			thread.Cancel(runContext.Err().Error())
		case <-cancelDone:
		}
	}()
	defer close(cancelDone)

	globals, err := compiled.program.Init(thread, starlark.StringDict{})
	if err != nil {
		err = normalizeRuntimeError(err)
		if ctx.Stderr != nil {
			ctx.Stderr(err.Error())
		}
		return RunResult{Stdout: output.String(), Output: output.String(), Stderr: err.Error()}, err
	}

	callable, ok := globals[entryPointName].(starlark.Callable)
	if !ok {
		return RunResult{}, fmt.Errorf("script %q does not expose %q", compiled.name, entryPointName)
	}

	if _, err := starlark.Call(thread, callable, starlark.Tuple{ctxValue}, nil); err != nil {
		err = normalizeRuntimeError(err)
		if ctx.Stderr != nil {
			ctx.Stderr(err.Error())
		}
		return RunResult{Stdout: output.String(), Output: output.String(), Stderr: err.Error()}, err
	}

	return RunResult{Stdout: output.String(), Output: output.String()}, nil
}

func Compile(name, source string) (*CompiledScript, error) {
	return CompileTransport(name, source)
}

func CompileTransport(name, source string) (*CompiledScript, error) {
	return compile(name, source, ScriptKindTransport)
}

func CompileGeneric(name, source string) (*CompiledScript, error) {
	return compile(name, source, ScriptKindGeneric)
}

func compile(name, source string, kind ScriptKind) (*CompiledScript, error) {
	_, program, err := starlark.SourceProgramOptions(scriptFileOptions, name, source, starlark.StringDict(nil).Has)
	if err != nil {
		return nil, err
	}

	thread := &starlark.Thread{Name: name, Load: newRuntimeLoad(ExecutionContext{}, false)}
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

	return &CompiledScript{name: name, program: program, kind: kind}, nil
}

func newRuntimeLoad(ctx ExecutionContext, allowRuntime bool) runtimeLoad {
	loads := map[string]starlark.StringDict{
		"kraken/bytes": {"bytes": sharedBytesModule},
		"kraken/time":  {"time": buildTimeModule(ctx.RunContext, allowRuntime)},
		"kraken/socket": {
			"socket": buildSocketModule(ctx, allowRuntime),
		},
	}
	return func(_ *starlark.Thread, module string) (starlark.StringDict, error) {
		globals, exists := loads[module]
		if !exists {
			return nil, fmt.Errorf("unsupported module %q", module)
		}
		return globals, nil
	}
}

func buildTimeModule(runContext context.Context, allowSleep bool) starlark.Value {
	if runContext == nil {
		runContext = context.Background()
	}
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
		timer := time.NewTimer(time.Duration(milliseconds) * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-runContext.Done():
			return nil, runContext.Err()
		}
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

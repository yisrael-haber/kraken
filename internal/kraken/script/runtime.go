package script

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	starlarkjson "go.starlark.net/lib/json"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"
)

const storedScriptCompileStepLimit = 5_000_000
const storedScriptCompileTimeout = time.Second

const (
	bytesModuleName      = "kraken/bytes"
	fragmentorModuleName = "kraken/fragmentor"
	timeModuleName       = "kraken/time"
	logModuleName        = "kraken/log"
	jsonModuleName       = "json"
	structModuleName     = "struct"
)

var scriptFileOptions = &syntax.FileOptions{
	While:           true,
	TopLevelControl: true,
	GlobalReassign:  true,
}

type runtimeOptions struct {
	AllowSleep bool
	Log        LogFunc
	PacketExec *packetExecutionState
}

type runtimeModuleRegistry struct {
	loads map[string]starlark.StringDict
}

type cachedRuntime struct {
	predeclared starlark.StringDict
	modules     *runtimeModuleRegistry
}

type runtimeModuleEntry struct {
	moduleName string
	binding    string
	value      starlark.Value
}

var (
	errScriptCompileTimedOut = errors.New("script validation timed out")
	sharedRuntimeOnce        sync.Once
	sharedBytesModule        starlark.Value
	sharedFragmentor         starlark.Value
	sharedStructBuiltin      starlark.Value
	sharedRuntimeErr         error
	sharedExecRuntime        cachedRuntime
	sharedExecOnce           sync.Once
	sharedExecRuntimeErr     error
	sharedCompileRuntime     cachedRuntime
	sharedCompileOnce        sync.Once
	sharedCompileErr         error
)

func Execute(compiled *CompiledScript, packet *MutablePacket, ctx ExecutionContext, logf LogFunc) (PacketExecutionResult, error) {
	return ExecuteWithDispatch(compiled, packet, ctx, logf, nil)
}

func ExecuteWithDispatch(compiled *CompiledScript, packet *MutablePacket, ctx ExecutionContext, logf LogFunc, dispatch func([]byte) error) (PacketExecutionResult, error) {
	return executeMutablePacketScript(compiled, SurfaceTransport, packet, ctx, logf, dispatch)
}

func executeMutablePacketScript(compiled *CompiledScript, surface Surface, packet *MutablePacket, ctx ExecutionContext, logf LogFunc, dispatch func([]byte) error) (PacketExecutionResult, error) {
	if err := validateExecutableScript(compiled, surface); err != nil {
		return PacketExecutionResult{}, err
	}

	ctxValue, err := newContextValue(ctx)
	if err != nil {
		return PacketExecutionResult{}, err
	}

	packetExec := &packetExecutionState{dispatch: dispatch}
	defer packetExec.cleanup(packet)
	thread, globals, err := initScriptGlobals(compiled, logf, packetExec)
	if err != nil {
		return PacketExecutionResult{}, err
	}

	mainValue := globals[entryPointName]
	callable, ok := mainValue.(starlark.Callable)
	if !ok {
		return PacketExecutionResult{}, fmt.Errorf("script %q does not expose %q", compiled.name, entryPointName)
	}

	if _, err := starlark.Call(thread, callable, starlark.Tuple{packet, ctxValue}, nil); err != nil {
		return PacketExecutionResult{}, normalizeRuntimeError(err)
	}

	if packet == nil {
		return packetExec.result(nil), nil
	}
	if err := packet.finalize(); err != nil {
		return PacketExecutionResult{}, err
	}
	return packetExec.result(packet), nil
}

func validateExecutableScript(compiled *CompiledScript, surface Surface) error {
	if compiled == nil || compiled.program == nil {
		return fmt.Errorf("%w: script is unavailable", ErrScriptInvalid)
	}
	if compiled.surface != surface {
		return fmt.Errorf("script %q uses %q surface, expected %q", compiled.name, compiled.surface, surface)
	}
	return nil
}

func initScriptGlobals(compiled *CompiledScript, logf LogFunc, packetExec *packetExecutionState) (*starlark.Thread, starlark.StringDict, error) {
	predeclared, modules, err := buildRuntime(runtimeOptions{
		AllowSleep: true,
		Log:        logf,
		PacketExec: packetExec,
	})
	if err != nil {
		return nil, nil, err
	}

	thread := newRuntimeThread(compiled.name, modules, runtimeOptions{
		AllowSleep: true,
		Log:        logf,
		PacketExec: packetExec,
	})

	globals, err := compiled.program.Init(thread, predeclared)
	if err != nil {
		return nil, nil, normalizeRuntimeError(err)
	}

	return thread, globals, nil
}

func Compile(name string, surface Surface, source string, allowSleep bool) (*CompiledScript, error) {
	predeclared, modules, err := buildRuntime(runtimeOptions{
		AllowSleep: allowSleep,
	})
	if err != nil {
		return nil, err
	}

	_, program, err := starlark.SourceProgramOptions(scriptFileOptions, name, source, predeclared.Has)
	if err != nil {
		return nil, err
	}

	thread := newRuntimeThread(name, modules, runtimeOptions{
		AllowSleep: allowSleep,
	})
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

func buildRuntime(options runtimeOptions) (starlark.StringDict, *runtimeModuleRegistry, error) {
	sharedRuntimeOnce.Do(func() {
		sharedBytesModule, sharedRuntimeErr = buildBytesModule()
		if sharedRuntimeErr != nil {
			return
		}
		sharedFragmentor = buildFragmentorModule(nil)
		sharedStructBuiltin = starlark.NewBuiltin("struct", starlarkstruct.Make)
	})
	if sharedRuntimeErr != nil {
		return nil, nil, sharedRuntimeErr
	}
	if options.Log == nil && options.PacketExec == nil {
		runtime, err := sharedRuntime(options.AllowSleep)
		if err != nil {
			return nil, nil, err
		}
		return runtime.predeclared, runtime.modules, nil
	}

	timeModule, err := buildTimeModule(options)
	if err != nil {
		return nil, nil, err
	}

	logModule, err := buildLogModule(options)
	if err != nil {
		return nil, nil, err
	}

	fragmentorModule := buildFragmentorModule(options.PacketExec)
	registry := newRuntimeModuleRegistry(timeModule, logModule, fragmentorModule)
	predeclared := newRuntimePredeclared()
	return predeclared, registry, nil
}

func sharedRuntime(allowSleep bool) (cachedRuntime, error) {
	if allowSleep {
		sharedExecOnce.Do(func() {
			sharedExecRuntime, sharedExecRuntimeErr = newCachedRuntime(runtimeOptions{AllowSleep: true})
		})
		return sharedExecRuntime, sharedExecRuntimeErr
	}

	sharedCompileOnce.Do(func() {
		sharedCompileRuntime, sharedCompileErr = newCachedRuntime(runtimeOptions{AllowSleep: false})
	})
	return sharedCompileRuntime, sharedCompileErr
}

func newCachedRuntime(options runtimeOptions) (cachedRuntime, error) {
	timeModule, err := buildTimeModule(options)
	if err != nil {
		return cachedRuntime{}, err
	}

	logModule, err := buildLogModule(options)
	if err != nil {
		return cachedRuntime{}, err
	}
	registry := newRuntimeModuleRegistry(timeModule, logModule, sharedFragmentor)

	return cachedRuntime{
		predeclared: newRuntimePredeclared(),
		modules:     registry,
	}, nil
}

func newRuntimeModuleRegistry(timeModule starlark.Value, logModule starlark.Value, fragmentorModule starlark.Value) *runtimeModuleRegistry {
	entries := []runtimeModuleEntry{
		{moduleName: bytesModuleName, binding: "bytes", value: sharedBytesModule},
		{moduleName: fragmentorModuleName, binding: "fragmentor", value: fragmentorModule},
		{moduleName: timeModuleName, binding: "time", value: timeModule},
		{moduleName: logModuleName, binding: "log", value: logModule},
		{moduleName: jsonModuleName, binding: "json", value: starlarkjson.Module},
		{moduleName: structModuleName, binding: "struct", value: sharedStructBuiltin},
	}

	loads := make(map[string]starlark.StringDict, len(entries))
	for _, entry := range entries {
		loads[entry.moduleName] = starlark.StringDict{entry.binding: entry.value}
	}

	return &runtimeModuleRegistry{
		loads: loads,
	}
}

func newRuntimePredeclared() starlark.StringDict {
	return starlark.StringDict{}
}

func newRuntimeThread(name string, modules *runtimeModuleRegistry, options runtimeOptions) *starlark.Thread {
	thread := &starlark.Thread{
		Name: name,
		Load: modules.load,
		Print: func(_ *starlark.Thread, message string) {
			if options.Log != nil {
				options.Log("info", message)
			}
		},
	}
	return thread
}

func (registry *runtimeModuleRegistry) load(_ *starlark.Thread, module string) (starlark.StringDict, error) {
	globals, exists := registry.loads[module]
	if !exists {
		return nil, fmt.Errorf("unsupported module %q", module)
	}
	return globals, nil
}

func buildTimeModule(options runtimeOptions) (starlark.Value, error) {
	sleepBuiltin := starlark.NewBuiltin("time.sleep", func(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if !options.AllowSleep {
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

	return module, nil
}

func buildLogModule(options runtimeOptions) (starlark.Value, error) {
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
			if options.Log != nil {
				if text, ok := starlark.AsString(message); ok {
					options.Log(levelName, text)
				} else {
					options.Log(levelName, message.String())
				}
			}
			return starlark.None, nil
		})
	}

	return module, nil
}

func normalizeRuntimeError(err error) error {
	var evalErr *starlark.EvalError
	if errors.As(err, &evalErr) {
		return fmt.Errorf("%s", strings.TrimSpace(evalErr.Backtrace()))
	}
	return err
}

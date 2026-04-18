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

var scriptFileOptions = &syntax.FileOptions{
	While:           true,
	TopLevelControl: true,
	GlobalReassign:  true,
}

type runtimeOptions struct {
	AllowSleep bool
	Log        LogFunc
}

type runtimeModuleRegistry struct {
	modules map[string]starlark.Value
	loads   map[string]starlark.StringDict
}

type cachedRuntime struct {
	predeclared starlark.StringDict
	modules     *runtimeModuleRegistry
}

var (
	sharedRuntimeOnce    sync.Once
	sharedBytesModule    starlark.Value
	sharedHTTPModule     starlark.Value
	sharedStructBuiltin  starlark.Value
	sharedRuntimeErr     error
	sharedExecRuntime    cachedRuntime
	sharedExecOnce       sync.Once
	sharedExecRuntimeErr error
	sharedCompileRuntime cachedRuntime
	sharedCompileOnce    sync.Once
	sharedCompileErr     error
)

func Execute(script StoredScript, packet *MutablePacket, ctx ExecutionContext, logf LogFunc) error {
	if err := validateExecutableScript(script, SurfacePacket); err != nil {
		return err
	}

	packetValue, err := newMutablePacketValue(packet)
	if err != nil {
		return err
	}
	ctxValue, err := newContextValue(ctx)
	if err != nil {
		return err
	}

	thread, globals, err := initScriptGlobals(script, logf)
	if err != nil {
		return err
	}

	mainValue := globals[entryPointName]
	callable, ok := mainValue.(starlark.Callable)
	if !ok {
		return fmt.Errorf("script %q does not expose %q", script.Name, entryPointName)
	}

	if _, err := starlark.Call(thread, callable, starlark.Tuple{packetValue, ctxValue}, nil); err != nil {
		return normalizeRuntimeError(err)
	}

	if packet == nil {
		return nil
	}
	return packet.finalize()
}

func validateExecutableScript(script StoredScript, surface Surface) error {
	if script.compiled == nil || script.compiled.program == nil {
		return fmt.Errorf("%w: script %q is unavailable", ErrStoredScriptInvalid, script.Name)
	}
	if script.Surface != surface {
		return fmt.Errorf("script %q uses %q surface, expected %q", script.Name, script.Surface, surface)
	}
	return nil
}

func initScriptGlobals(script StoredScript, logf LogFunc) (*starlark.Thread, starlark.StringDict, error) {
	predeclared, modules, err := buildRuntime(runtimeOptions{
		AllowSleep: true,
		Log:        logf,
	})
	if err != nil {
		return nil, nil, err
	}

	thread := newRuntimeThread(script.Name, modules, runtimeOptions{
		AllowSleep: true,
		Log:        logf,
	})

	globals, err := script.compiled.program.Init(thread, predeclared)
	if err != nil {
		return nil, nil, normalizeRuntimeError(err)
	}

	return thread, globals, nil
}

func buildRuntime(options runtimeOptions) (starlark.StringDict, *runtimeModuleRegistry, error) {
	sharedRuntimeOnce.Do(func() {
		sharedBytesModule, sharedRuntimeErr = buildBytesModule()
		if sharedRuntimeErr != nil {
			return
		}
		sharedHTTPModule, sharedRuntimeErr = buildHTTPModule()
		if sharedRuntimeErr != nil {
			return
		}
		sharedStructBuiltin = starlark.NewBuiltin("struct", starlarkstruct.Make)
	})
	if sharedRuntimeErr != nil {
		return nil, nil, sharedRuntimeErr
	}
	if options.Log == nil {
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

	registry := newRuntimeModuleRegistry(timeModule, logModule)
	predeclared := newRuntimePredeclared(registry, timeModule, logModule)
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
	registry := newRuntimeModuleRegistry(timeModule, logModule)

	return cachedRuntime{
		predeclared: newRuntimePredeclared(registry, timeModule, logModule),
		modules:     registry,
	}, nil
}

func newRuntimeModuleRegistry(timeModule starlark.Value, logModule starlark.Value) *runtimeModuleRegistry {
	return &runtimeModuleRegistry{
		modules: map[string]starlark.Value{
			"kraken/bytes": sharedBytesModule,
			"kraken/http":  sharedHTTPModule,
			"kraken/time":  timeModule,
			"kraken/log":   logModule,
			"json":         starlarkjson.Module,
			"struct":       sharedStructBuiltin,
		},
		loads: map[string]starlark.StringDict{
			"kraken/bytes": {"bytes": sharedBytesModule},
			"kraken/http":  {"http": sharedHTTPModule},
			"kraken/time":  {"time": timeModule},
			"kraken/log":   {"log": logModule},
			"json":         {"json": starlarkjson.Module},
			"struct":       {"struct": sharedStructBuiltin},
		},
	}
}

func newRuntimePredeclared(registry *runtimeModuleRegistry, timeModule starlark.Value, logModule starlark.Value) starlark.StringDict {
	return starlark.StringDict{
		"require": starlark.NewBuiltin("require", registry.require),
		"bytes":   sharedBytesModule,
		"http":    sharedHTTPModule,
		"time":    timeModule,
		"log":     logModule,
		"json":    starlarkjson.Module,
		"struct":  sharedStructBuiltin,
	}
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

func (registry *runtimeModuleRegistry) require(_ *starlark.Thread, builtin *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var module string
	if err := starlark.UnpackPositionalArgs(builtin.Name(), args, kwargs, 1, &module); err != nil {
		return nil, err
	}

	value, exists := registry.modules[module]
	if !exists {
		return nil, fmt.Errorf("unsupported module %q", module)
	}
	return value, nil
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

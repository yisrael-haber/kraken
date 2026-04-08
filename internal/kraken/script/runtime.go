package script

import (
	"fmt"
	"math"
	"time"

	"github.com/dop251/goja"
	packetpkg "github.com/yisrael-haber/kraken/internal/kraken/packet"
)

type runtimeOptions struct {
	AllowSleep bool
	Log        LogFunc
}

func Execute(script StoredScript, packet *packetpkg.OutboundPacket, ctx ExecutionContext, logf LogFunc) error {
	if script.compiled == nil || script.compiled.program == nil {
		return fmt.Errorf("%w: script %q is unavailable", ErrStoredScriptInvalid, script.Name)
	}

	vm := goja.New()
	if err := installRuntime(vm, runtimeOptions{
		AllowSleep: true,
		Log:        logf,
	}); err != nil {
		return err
	}

	packetValue, err := newPacketValue(vm, packet)
	if err != nil {
		return err
	}
	ctxValue := newContextValue(vm, ctx)

	if _, err := vm.RunProgram(script.compiled.program); err != nil {
		return err
	}

	mainValue := vm.Get(entryPointName)
	mainFunc, ok := goja.AssertFunction(mainValue)
	if !ok {
		return fmt.Errorf("script %q does not expose %q", script.Name, entryPointName)
	}

	if _, err := mainFunc(goja.Undefined(), packetValue, ctxValue); err != nil {
		return err
	}

	return applyPacketValue(vm, packetValue, packet)
}

func installRuntime(vm *goja.Runtime, options runtimeOptions) error {
	moduleCache := map[string]goja.Value{}

	if err := vm.Set("require", func(call goja.FunctionCall) goja.Value {
		name := call.Argument(0).String()
		if cached, exists := moduleCache[name]; exists {
			return cached
		}

		module, err := buildModule(vm, name, options)
		if err != nil {
			panic(vm.ToValue(err.Error()))
		}

		moduleCache[name] = module
		return module
	}); err != nil {
		return err
	}

	return nil
}

func buildModule(vm *goja.Runtime, name string, options runtimeOptions) (goja.Value, error) {
	switch name {
	case "kraken/time":
		module := vm.NewObject()
		if err := module.Set("nowMs", func() int64 {
			return time.Now().UnixMilli()
		}); err != nil {
			return nil, err
		}
		if err := module.Set("sleep", func(call goja.FunctionCall) goja.Value {
			if !options.AllowSleep {
				panic(vm.ToValue("kraken/time.sleep is unavailable during validation"))
			}

			duration := call.Argument(0).ToFloat()
			if math.IsNaN(duration) || duration < 0 {
				panic(vm.ToValue("kraken/time.sleep requires a non-negative millisecond duration"))
			}
			time.Sleep(time.Duration(duration * float64(time.Millisecond)))
			return goja.Undefined()
		}); err != nil {
			return nil, err
		}

		return module, nil
	case "kraken/log":
		module := vm.NewObject()
		for _, level := range []string{"info", "warn", "error"} {
			levelName := level
			if err := module.Set(levelName, func(call goja.FunctionCall) goja.Value {
				if options.Log != nil {
					options.Log(levelName, call.Argument(0).String())
				}
				return goja.Undefined()
			}); err != nil {
				return nil, err
			}
		}

		return module, nil
	default:
		return nil, fmt.Errorf("unsupported module %q", name)
	}
}

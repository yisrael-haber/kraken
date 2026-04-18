package script

import (
	"fmt"

	"go.starlark.net/starlark"
)

func ExecuteTLSStream(script StoredScript, data *StreamData, ctx StreamExecutionContext, logf LogFunc) error {
	return executeStream(script, SurfaceTLSService, data, ctx, logf)
}

func ExecuteSSHStream(script StoredScript, data *StreamData, ctx StreamExecutionContext, logf LogFunc) error {
	return executeStream(script, SurfaceSSHService, data, ctx, logf)
}

func executeStream(script StoredScript, surface Surface, data *StreamData, ctx StreamExecutionContext, logf LogFunc) error {
	if err := validateExecutableScript(script, surface); err != nil {
		return err
	}

	dataValue := newStreamDataValue(data)
	ctxValue, err := newStreamContextValue(ctx)
	if err != nil {
		return err
	}

	thread, globals, err := initScriptGlobals(script, logf, nil)
	if err != nil {
		return err
	}

	mainValue := globals[entryPointName]
	callable, ok := mainValue.(starlark.Callable)
	if !ok {
		return fmt.Errorf("script %q does not expose %q", script.Name, entryPointName)
	}

	if _, err := starlark.Call(thread, callable, starlark.Tuple{dataValue, ctxValue}, nil); err != nil {
		return normalizeRuntimeError(err)
	}

	return applyStreamDataValue(dataValue, data)
}

func newStreamContextValue(ctx StreamExecutionContext) (starlark.Value, error) {
	fields := starlark.StringDict{
		"scriptName": starlark.String(ctx.ScriptName),
		"adopted": newScriptObject("ctx.adopted", false, starlark.StringDict{
			"label":          starlark.String(ctx.Adopted.Label),
			"ip":             starlark.String(ctx.Adopted.IP),
			"mac":            starlark.String(ctx.Adopted.MAC),
			"interfaceName":  starlark.String(ctx.Adopted.InterfaceName),
			"defaultGateway": starlark.String(ctx.Adopted.DefaultGateway),
			"mtu":            starlark.MakeInt(ctx.Adopted.MTU),
		}),
		"service": newScriptObject("ctx.service", false, starlark.StringDict{
			"name":          starlark.String(ctx.Service.Name),
			"port":          starlark.MakeInt(ctx.Service.Port),
			"protocol":      starlark.String(ctx.Service.Protocol),
			"rootDirectory": starlark.String(ctx.Service.RootDirectory),
			"useTLS":        starlark.Bool(ctx.Service.UseTLS),
		}),
		"connection": newScriptObject("ctx.connection", false, starlark.StringDict{
			"localAddress":  starlark.String(ctx.Connection.LocalAddress),
			"remoteAddress": starlark.String(ctx.Connection.RemoteAddress),
		}),
		"metadata": starlark.None,
	}

	if len(ctx.Metadata) != 0 {
		metadata, err := toStarlarkValue(ctx.Metadata)
		if err != nil {
			return nil, fmt.Errorf("ctx.metadata: %w", err)
		}
		fields["metadata"] = metadata
	}

	return newScriptObject("ctx", false, fields), nil
}

func newStreamDataValue(data *StreamData) *scriptObject {
	if data == nil {
		data = &StreamData{}
	}

	return newScriptObject("stream", true, starlark.StringDict{
		"direction": starlark.String(data.Direction),
		"payload":   newBorrowedByteBuffer(data.Payload),
	})
}

func applyStreamDataValue(value starlark.Value, data *StreamData) error {
	if data == nil || isNone(value) {
		return nil
	}

	payloadValue, err := attrOrNone(value, "payload")
	if err != nil {
		return fmt.Errorf("stream.payload: %w", err)
	}
	payload, err := parseOptionalBytes(payloadValue)
	if err != nil {
		return fmt.Errorf("stream.payload: %w", err)
	}
	data.Payload = payload
	return nil
}

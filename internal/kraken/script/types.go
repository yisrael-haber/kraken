package script

import (
	"errors"

	"github.com/dop251/goja"
)

const (
	storedScriptFolder = "scripts"
	entryPointName     = "main"
)

var (
	ErrStoredScriptNotFound = errors.New("stored script was not found")
	ErrStoredScriptInvalid  = errors.New("stored script is invalid")
)

type StoredScript struct {
	Name         string          `json:"name"`
	Source       string          `json:"source"`
	EntryPoint   string          `json:"entryPoint"`
	Available    bool            `json:"available"`
	CompileError string          `json:"compileError,omitempty"`
	UpdatedAt    string          `json:"updatedAt,omitempty"`
	compiled     *compiledScript `json:"-"`
	modules      map[string]bool `json:"-"`
}

type compiledScript struct {
	program *goja.Program
}

type StoredScriptSummary struct {
	Name         string `json:"name"`
	EntryPoint   string `json:"entryPoint"`
	Available    bool   `json:"available"`
	CompileError string `json:"compileError,omitempty"`
	UpdatedAt    string `json:"updatedAt,omitempty"`
}

type SaveStoredScriptRequest struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

type LogFunc func(level, message string)

type ExecutionContext struct {
	ScriptName string                 `json:"scriptName"`
	SendPath   string                 `json:"sendPath"`
	Protocol   string                 `json:"protocol"`
	Adopted    ExecutionIdentity      `json:"adopted"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type ExecutionIdentity struct {
	Label          string `json:"label"`
	IP             string `json:"ip"`
	MAC            string `json:"mac"`
	InterfaceName  string `json:"interfaceName"`
	DefaultGateway string `json:"defaultGateway,omitempty"`
}

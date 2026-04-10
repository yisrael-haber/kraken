package main

import (
	"reflect"
	"testing"
)

func TestAppExposesBoundRuntimeMethods(t *testing.T) {
	appType := reflect.TypeOf(NewApp())

	for _, name := range []string{
		"ListAdoptionInterfaces",
		"AdoptIPAddress",
		"ListStoredScriptNames",
		"SaveStoredScript",
		"ChooseAdoptedIPAddressRecordingPath",
		"StartAdoptedIPAddressRecording",
		"StopAdoptedIPAddressRecording",
		"UpdateAdoptedIPAddressScriptBindings",
		"PingAdoptedIPAddress",
	} {
		if _, ok := appType.MethodByName(name); !ok {
			t.Fatalf("expected App to expose %s", name)
		}
	}
}

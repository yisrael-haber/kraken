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
		"ChooseServiceDirectory",
		"ListManagedServices",
		"ListServiceDefinitions",
		"SaveStoredScript",
		"ChooseAdoptedIPAddressRecordingPath",
		"StartAdoptedIPAddressRecording",
		"StopAdoptedIPAddressRecording",
		"StartAdoptedIPAddressService",
		"StopAdoptedIPAddressService",
		"UpdateAdoptedIPAddressScript",
		"PingAdoptedIPAddress",
	} {
		if _, ok := appType.MethodByName(name); !ok {
			t.Fatalf("expected App to expose %s", name)
		}
	}
}

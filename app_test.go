package main

import (
	"reflect"
	"testing"
)

func TestAppExposesBoundRuntimeMethods(t *testing.T) {
	app := NewApp()
	appType := reflect.TypeOf(app)

	for _, name := range []string{
		"ListAdoptionInterfaces",
		"ChooseDirectory",
		"ResetSignalHandlers",
	} {
		if _, ok := appType.MethodByName(name); !ok {
			t.Fatalf("expected App to expose %s", name)
		}
	}

	managerType := reflect.TypeOf(&ManagerAPI{Manager: app.manager})
	for _, name := range []string{
		"AdoptIPAddress",
		"SaveStoredScript",
		"StartAdoptedIPAddressRecording",
		"StopAdoptedIPAddressRecording",
		"StartAdoptedIPAddressService",
		"StopAdoptedIPAddressService",
		"UpdateAdoptedIPAddressMTU",
		"UpdateAdoptedIPAddressScripts",
		"ResolveDNSAdoptedIPAddress",
	} {
		if _, ok := managerType.MethodByName(name); !ok {
			t.Fatalf("expected ManagerAPI to expose %s", name)
		}
	}
}

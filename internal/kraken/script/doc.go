// Package script owns Kraken's Starlark runtime.
//
// It intentionally exposes two independent execution surfaces:
// transport scripts mutate post-netstack packet frames before NIC dispatch,
// while application scripts mutate managed-service byte buffers before or
// after service code handles them. The surfaces share runtime modules and
// value conversion helpers, but their entrypoint arguments and mutation
// lifecycles stay separate.
package script

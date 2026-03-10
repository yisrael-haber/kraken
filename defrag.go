package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
)

// defragPacket processes pkt through the defragmenter.
//
// Non-IPv4 packets (ARP, IPv6, etc.) are returned unchanged.
// Non-fragmented IPv4 packets are returned unchanged.
// IP fragments are buffered until all pieces arrive; once reassembly is
// complete the function returns a new packet built from the original Ethernet
// header and the reassembled IPv4 datagram.
//
// Returns (nil, nil) when a fragment was buffered but reassembly is not yet
// complete — the caller should skip that packet and continue its loop.
func defragPacket(defragger *ip4defrag.IPv4Defragmenter, pkt gopacket.Packet) (gopacket.Packet, error) {
	ip4Layer, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		return pkt, nil // not IPv4 — ARP, IPv6, etc.
	}

	// Fast path: not a fragment.
	if ip4Layer.Flags&layers.IPv4MoreFragments == 0 && ip4Layer.FragOffset == 0 {
		return pkt, nil
	}

	newIP4, err := defragger.DefragIPv4(ip4Layer)
	if err != nil {
		return nil, err
	}
	if newIP4 == nil {
		return nil, nil // fragment buffered; reassembly not yet complete
	}

	// Reassembly complete. Rebuild an Ethernet-framed packet so that callers
	// can continue using the same layer-extraction logic they already have.
	ethLayer, ok := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if !ok {
		// No Ethernet header (shouldn't happen on our handles).
		return gopacket.NewPacket(newIP4.Payload, newIP4.NextLayerType(), gopacket.Default), nil
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ethLayer, newIP4, gopacket.Payload(newIP4.Payload)); err != nil {
		return nil, err
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default), nil
}

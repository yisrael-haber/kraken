//go:build windows

package main

import "errors"

func startSwap(_ *swapSession) error {
	return errors.New(
		"swap is not supported on Windows.\n\n" +
			"On Linux, swap uses nftables + NFQUEUE to intercept the targeted\n" +
			"3-tuple at the kernel level, giving Kraken exclusive ownership of\n" +
			"those packets without disrupting other traffic.\n\n" +
			"The Windows equivalent requires WinDivert, which hooks into the\n" +
			"Windows Filtering Platform (WFP) to provide the same capability.\n" +
			"WinDivert support has not been implemented yet.")
}

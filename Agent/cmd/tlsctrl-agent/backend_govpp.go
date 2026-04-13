//go:build govpp

package main

import (
	"tlsctrl-agent/internal/config"
	"tlsctrl-agent/internal/vppclient"
	"tlsctrl-agent/internal/vppclient/govppbackend"
)

func newGovPPBackend(cfg config.Config) (vppclient.Client, error) {
	return govppbackend.New(cfg.VPPAPISocket, cfg.GovPPTimeout, cfg.VerboseLogging)
}

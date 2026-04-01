//go:build govpp

package main

import (
	"github.com/srmkv/tlsctrl-agent/internal/config"
	"github.com/srmkv/tlsctrl-agent/internal/vppclient"
	"github.com/srmkv/tlsctrl-agent/internal/vppclient/govppbackend"
)

func newGovPPBackend(cfg config.Config) (vppclient.Client, error) {
	return govppbackend.New(cfg.VPPAPISocket, cfg.GovPPTimeout, cfg.VerboseLogging)
}

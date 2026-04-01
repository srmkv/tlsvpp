//go:build !govpp

package main

import (
	"fmt"

	"github.com/srmkv/tlsctrl-agent/internal/config"
	"github.com/srmkv/tlsctrl-agent/internal/vppclient"
)

func newGovPPBackend(cfg config.Config) (vppclient.Client, error) {
	return nil, fmt.Errorf("govpp backend selected, but this build does not include it; generate binapi bindings and build with: go build -tags govpp ./cmd/tlsctrl-agent")
}

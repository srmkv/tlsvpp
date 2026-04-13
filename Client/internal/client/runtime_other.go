//go:build !linux

package client

import (
	"context"
	"os"
)

type runtimeApplyInput struct {
	AssignedIP    string
	Gateway       string
	DNSServers    string
	IncludeRoutes string
	ExcludeRoutes string
	FullTunnel    bool
	MTU           int
}

type runtimeApplier struct{}
type runtimeState struct{}

func newRuntimeApplier() *runtimeApplier { return &runtimeApplier{} }
func (a *runtimeApplier) Apply(ctx context.Context, in runtimeApplyInput) (*runtimeState, error) {
	return &runtimeState{}, nil
}
func (a *runtimeApplier) Revert(ctx context.Context) error { return nil }
func (a *runtimeApplier) TunFile() *os.File                { return nil }
func (a *runtimeApplier) TunReadFile() *os.File            { return nil }
func (a *runtimeApplier) TunWriteFile() *os.File           { return nil }
func (a *runtimeApplier) InterfaceName() string            { return "tlsvpn0" }

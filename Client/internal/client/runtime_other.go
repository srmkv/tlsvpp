//go:build !linux

package client

import "context"

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
func (a *runtimeApplier) Apply(ctx context.Context, in runtimeApplyInput) (*runtimeState, error) { return &runtimeState{}, nil }
func (a *runtimeApplier) Revert(ctx context.Context) error { return nil }

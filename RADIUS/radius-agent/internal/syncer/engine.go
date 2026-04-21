package syncer

import (
	"context"
	"fmt"
	"log"

	"radius-agent/internal/integration/controlplane"
	"radius-agent/internal/model"
	"radius-agent/internal/resolver"
	"radius-agent/internal/source"
	"radius-agent/internal/store"
)

// Engine syncs a single source and optionally pushes results to the control plane.
type Engine struct {
	store    store.Store
	adapter  source.Adapter
	cp       *controlplane.Client
	resolver *resolver.Service
}

// New creates an Engine. cp may be nil or disabled (cp.Enabled()==false) to
// skip the push step.
func New(st store.Store, ad source.Adapter, cp *controlplane.Client) *Engine {
	return &Engine{
		store:    st,
		adapter:  ad,
		cp:       cp,
		resolver: resolver.New(st),
	}
}

// SyncSource loads a fresh snapshot from the RADIUS SQL backend, persists it
// locally, then pushes resolved user records to the tlsagent control plane.
func (e *Engine) SyncSource(ctx context.Context, sourceID string) (*model.Snapshot, error) {
	src, _, err := e.store.GetSource(ctx, sourceID)
	if err != nil {
		return nil, err
	}
	if !src.Enabled {
		return nil, fmt.Errorf("source %s disabled", sourceID)
	}

	snap, err := e.adapter.LoadSnapshot(ctx, *src)
	if err != nil {
		return nil, fmt.Errorf("load snapshot source=%s: %w", sourceID, err)
	}

	if err := e.store.SaveSnapshot(ctx, sourceID, snap); err != nil {
		return nil, fmt.Errorf("save snapshot source=%s: %w", sourceID, err)
	}

	log.Printf("syncer: source=%s users=%d groups=%d hash=%s",
		sourceID, snap.Diagnostics.UserCount, snap.Diagnostics.GroupCount, snap.Diagnostics.Hash[:8])

	// Push resolved users to tlsagent (non-fatal on failure)
	if e.cp != nil && e.cp.Enabled() {
		if err := e.pushToControlPlane(ctx, snap); err != nil {
			log.Printf("syncer: push to control-plane source=%s err=%v (local sync still succeeded)", sourceID, err)
		}
	}

	return snap, nil
}

// pushToControlPlane resolves every user in the snapshot to a VPN profile
// and pushes the resulting list to tlsagent.
func (e *Engine) pushToControlPlane(ctx context.Context, snap *model.Snapshot) error {
	records := make([]controlplane.UserRecord, 0, len(snap.Users))
	for _, u := range snap.Users {
		policy, err := e.resolver.ResolveUser(ctx, snap.SourceID, u.Username)
		if err != nil {
			// User has no group mapping → skip (they won't be importable without a profile)
			log.Printf("syncer: resolve user=%s source=%s err=%v (skipping push)", u.Username, snap.SourceID, err)
			continue
		}
		profile := policy.VPNProfile
		if profile == "" {
			profile = "default"
		}
		records = append(records, controlplane.UserRecord{
			Username: u.Username,
			Profile:  profile,
			Enabled:  !u.Disabled,
			Source:   snap.SourceID,
		})
	}

	result, err := e.cp.PushUsers(ctx, records)
	if err != nil {
		return err
	}
	if result != nil {
		log.Printf("syncer: push complete source=%s users=%d created=%d updated=%d skipped=%d errors=%d",
			snap.SourceID, len(records), result.Created, result.Updated, result.Skipped, len(result.Errors))
		for _, e := range result.Errors {
			log.Printf("syncer: push error source=%s: %s", snap.SourceID, e)
		}
	}
	return nil
}

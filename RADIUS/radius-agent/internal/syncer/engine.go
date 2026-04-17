package syncer

import (
	"context"
	"fmt"
	"radius-agent/internal/model"
	"radius-agent/internal/source"
	"radius-agent/internal/store"
)

type Engine struct {
	store   store.Store
	adapter source.Adapter
}

func New(st store.Store, ad source.Adapter) *Engine { return &Engine{store: st, adapter: ad} }

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
		return nil, err
	}
	if err := e.store.SaveSnapshot(ctx, sourceID, snap); err != nil {
		return nil, err
	}
	return snap, nil
}

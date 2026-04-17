package store

import (
	"context"
	"radius-agent/internal/model"
)

type Store interface {
	UpsertSource(ctx context.Context, src model.Source, syncEverySec int) error
	ListSources(ctx context.Context) ([]model.Source, map[string]int, error)
	GetSource(ctx context.Context, sourceID string) (*model.Source, int, error)

	SaveSnapshot(ctx context.Context, sourceID string, snap *model.Snapshot) error
	GetLatestSnapshot(ctx context.Context, sourceID string) (*model.Snapshot, error)

	SaveGroupMappings(ctx context.Context, items []model.GroupMapping) error
	ListGroupMappings(ctx context.Context) ([]model.GroupMapping, error)

	SaveAttrMappings(ctx context.Context, items []model.AttrMapping) error
	ListAttrMappings(ctx context.Context) ([]model.AttrMapping, error)
}

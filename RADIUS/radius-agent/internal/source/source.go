package source

import (
	"context"
	"radius-agent/internal/model"
)

type Adapter interface {
	Ping(ctx context.Context, src model.Source) error
	LoadSnapshot(ctx context.Context, src model.Source) (*model.Snapshot, error)
}

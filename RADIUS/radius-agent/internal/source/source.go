// Package source defines the Adapter interface and a MultiAdapter dispatcher
// that routes each sync request to the correct backend implementation based
// on the source Type field.
package source

import (
	"context"
	"fmt"
	"radius-agent/internal/model"
)

// Adapter can load a full user/group snapshot from a single RADIUS data source.
type Adapter interface {
	Ping(ctx context.Context, src model.Source) error
	LoadSnapshot(ctx context.Context, src model.Source) (*model.Snapshot, error)
}

// MultiAdapter dispatches to the right Adapter based on src.Type.
// Unknown types return an explicit "unsupported source type" error so they are
// visible in logs instead of falling through to a mismatched driver.
type MultiAdapter struct {
	adapters map[model.SourceType]Adapter
}

// NewMultiAdapter creates a dispatcher pre-loaded with the given adapters.
// Call Register to add more at runtime.
func NewMultiAdapter(m map[model.SourceType]Adapter) *MultiAdapter {
	if m == nil {
		m = map[model.SourceType]Adapter{}
	}
	return &MultiAdapter{adapters: m}
}

func (m *MultiAdapter) Register(t model.SourceType, a Adapter) {
	m.adapters[t] = a
}

func (m *MultiAdapter) Ping(ctx context.Context, src model.Source) error {
	a, err := m.get(src.Type)
	if err != nil {
		return err
	}
	return a.Ping(ctx, src)
}

func (m *MultiAdapter) LoadSnapshot(ctx context.Context, src model.Source) (*model.Snapshot, error) {
	a, err := m.get(src.Type)
	if err != nil {
		return nil, err
	}
	return a.LoadSnapshot(ctx, src)
}

func (m *MultiAdapter) get(t model.SourceType) (Adapter, error) {
	if a, ok := m.adapters[t]; ok {
		return a, nil
	}
	supported := make([]string, 0, len(m.adapters))
	for k := range m.adapters {
		supported = append(supported, string(k))
	}
	return nil, fmt.Errorf(
		"неизвестный тип источника %q. Поддерживаются: %v",
		t, supported,
	)
}

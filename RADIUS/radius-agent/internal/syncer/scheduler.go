package syncer

import (
	"context"
	"log"
	"radius-agent/internal/store"
	"time"
)

type Scheduler struct {
	store  store.Store
	engine *Engine
}

func NewScheduler(st store.Store, eng *Engine) *Scheduler { return &Scheduler{store: st, engine: eng} }

func (s *Scheduler) Run(ctx context.Context, defaultInterval time.Duration) {
	ticker := time.NewTicker(defaultInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sources, _, err := s.store.ListSources(ctx)
			if err != nil {
				log.Printf("radius-agent: list sources: %v", err)
				continue
			}
			for _, src := range sources {
				if !src.Enabled {
					continue
				}
				if _, err := s.engine.SyncSource(ctx, src.ID); err != nil {
					log.Printf("radius-agent: sync source=%s err=%v", src.ID, err)
				}
			}
		}
	}
}

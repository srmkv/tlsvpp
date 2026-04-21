package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"tlsctrl-agent/internal/model"
)

func normalizeShardNode(n model.ShardNode) model.ShardNode {
	n.Name = strings.TrimSpace(n.Name)
	n.ClientPublicURL = strings.TrimSpace(n.ClientPublicURL)
	n.ServerName = strings.TrimSpace(n.ServerName)
	if n.Weight <= 0 {
		n.Weight = 1
	}
	if n.UpdatedAt.IsZero() {
		n.UpdatedAt = time.Now().UTC()
	}
	return n
}

func (s *Service) implicitLocalShard() model.ShardNode {
	settings, _ := s.CurrentSettings()
	url := strings.TrimSpace(settings.ClientPublicURL)
	serverName := strings.TrimSpace(settings.ServerName)
	if url == "" && s.pki != nil {
		url = strings.TrimSpace(s.pki.ClientURL)
	}
	if serverName == "" && s.pki != nil {
		serverName = strings.TrimSpace(s.pki.ServerName)
	}
	return normalizeShardNode(model.ShardNode{
		Name: "local", ClientPublicURL: url, ServerName: serverName,
		Enabled: true, Weight: 1, UpdatedAt: time.Now().UTC(),
	})
}

// ensureShards seeds the implicit local shard if the store is empty.
func (s *Service) ensureShards(ctx context.Context) ([]model.ShardNode, error) {
	shards, err := s.store.ListShards(ctx)
	if err != nil {
		return nil, err
	}
	if len(shards) == 0 {
		local := s.implicitLocalShard()
		if uerr := s.store.UpsertShard(ctx, local); uerr != nil {
			return nil, uerr
		}
		return []model.ShardNode{local}, nil
	}
	for i := range shards {
		shards[i] = normalizeShardNode(shards[i])
	}
	sort.Slice(shards, func(i, j int) bool { return shards[i].Name < shards[j].Name })
	return shards, nil
}

func (s *Service) Shards(ctx context.Context) ([]model.ShardNodeView, error) {
	shards, err := s.ensureShards(ctx)
	if err != nil {
		return nil, err
	}
	placements, err := s.store.ListPlacements(ctx)
	if err != nil {
		return nil, err
	}
	sessions, _ := s.backend.ListSessions(ctx)

	assigned := map[string]int{}
	connected := map[string]int{}
	placementMap := map[string]model.ShardPlacement{}
	for _, p := range placements {
		assigned[p.ShardName]++
		placementMap[p.Username] = model.ShardPlacement{ShardName: p.ShardName}
	}
	for _, sess := range sessions {
		if !sess.Connected {
			continue
		}
		if p, ok := placementMap[sess.Username]; ok {
			connected[p.ShardName]++
		}
	}
	out := make([]model.ShardNodeView, 0, len(shards))
	for _, sh := range shards {
		out = append(out, model.ShardNodeView{
			ShardNode:      sh,
			AssignedUsers:  assigned[sh.Name],
			ConnectedUsers: connected[sh.Name],
			EffectiveWeight: maxInt(1, sh.Weight),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (s *Service) UpsertShard(ctx context.Context, n model.ShardNode) error {
	n = normalizeShardNode(n)
	if n.Name == "" {
		return errors.New("shard name is required")
	}
	if n.ClientPublicURL == "" {
		return errors.New("client_public_url is required")
	}
	return s.store.UpsertShard(ctx, n)
}

func (s *Service) DeleteShard(ctx context.Context, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("shard name is required")
	}
	shards, err := s.store.ListShards(ctx)
	if err != nil {
		return err
	}
	remaining := 0
	for _, sh := range shards {
		if !strings.EqualFold(sh.Name, name) {
			remaining++
		}
	}
	if remaining == 0 {
		return errors.New("cannot delete last shard")
	}
	if err := s.store.DeleteShard(ctx, name); err != nil {
		return err
	}
	// Remove placements pointing to deleted shard
	placements, err := s.store.ListPlacements(ctx)
	if err == nil {
		for _, p := range placements {
			if strings.EqualFold(p.ShardName, name) {
				_ = s.store.DeletePlacement(ctx, p.Username)
			}
		}
	}
	return nil
}

func (s *Service) chooseShardForUser(ctx context.Context, username string) (model.ShardNode, error) {
	shards, err := s.ensureShards(ctx)
	if err != nil {
		return model.ShardNode{}, err
	}
	placements, err := s.store.ListPlacements(ctx)
	if err != nil {
		return model.ShardNode{}, err
	}
	// Check if user already has a valid placement
	for _, p := range placements {
		if strings.EqualFold(p.Username, username) {
			for _, sh := range shards {
				if strings.EqualFold(sh.Name, p.ShardName) && sh.Enabled && sh.ClientPublicURL != "" {
					return sh, nil
				}
			}
			break
		}
	}
	// Pick shard with lowest assigned_users/weight score
	assigned := map[string]int{}
	for _, p := range placements {
		assigned[p.ShardName]++
	}
	type candidate struct {
		sh    model.ShardNode
		score float64
	}
	cands := make([]candidate, 0, len(shards))
	for _, sh := range shards {
		if !sh.Enabled || strings.TrimSpace(sh.ClientPublicURL) == "" {
			continue
		}
		w := maxInt(1, sh.Weight)
		score := float64(assigned[sh.Name]) / float64(w)
		if sh.CapacityHint > 0 {
			score += float64(assigned[sh.Name]) / float64(maxInt(1, sh.CapacityHint))
		}
		cands = append(cands, candidate{sh: sh, score: score})
	}
	if len(cands) == 0 {
		return model.ShardNode{}, errors.New("no enabled shard nodes configured")
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].score == cands[j].score {
			return cands[i].sh.Name < cands[j].sh.Name
		}
		return cands[i].score < cands[j].score
	})
	chosen := cands[0].sh
	now := time.Now().UTC()
	if err := s.store.SetPlacement(ctx, model.ShardPlacement{
		Username: username, ShardName: chosen.Name,
		ClientPublicURL: chosen.ClientPublicURL, ServerName: chosen.ServerName,
		AssignedAt: now, UpdatedAt: now,
	}); err != nil {
		return model.ShardNode{}, err
	}
	return chosen, nil
}

func (s *Service) placementForUser(ctx context.Context, username string) (model.ShardPlacement, bool) {
	p, err := s.store.GetPlacement(ctx, strings.ToLower(strings.TrimSpace(username)))
	if err != nil {
		return model.ShardPlacement{}, false
	}
	return p, true
}

func (s *Service) shardSummary(ctx context.Context) map[string]any {
	views, err := s.Shards(ctx)
	if err != nil {
		return map[string]any{"count": 0}
	}
	enabled, assigned, connected := 0, 0, 0
	for _, v := range views {
		if v.Enabled {
			enabled++
		}
		assigned += v.AssignedUsers
		connected += v.ConnectedUsers
	}
	return map[string]any{
		"count": len(views), "enabled": enabled,
		"assigned_users": assigned, "connected_users": connected, "nodes": views,
	}
}

func (s *Service) BundlePlacement(ctx context.Context, username string) (map[string]any, error) {
	sh, err := s.chooseShardForUser(ctx, strings.TrimSpace(username))
	if err != nil {
		return nil, err
	}
	p, _ := s.placementForUser(ctx, strings.TrimSpace(username))
	return map[string]any{
		"username": username, "client_public_url": sh.ClientPublicURL,
		"server_name": sh.ServerName, "assigned_shard": sh.Name, "placement": p,
	}, nil
}

func (s *Service) updatePlacement(ctx context.Context, username string, sh model.ShardNode) error {
	existing, _ := s.store.GetPlacement(ctx, username)
	now := time.Now().UTC()
	assignedAt := existing.AssignedAt
	if assignedAt.IsZero() || !strings.EqualFold(existing.ShardName, sh.Name) {
		assignedAt = now
	}
	return s.store.SetPlacement(ctx, model.ShardPlacement{
		Username: username, ShardName: sh.Name,
		ClientPublicURL: sh.ClientPublicURL, ServerName: sh.ServerName,
		AssignedAt: assignedAt, UpdatedAt: now,
	})
}

func (s *Service) issueBundleWithAutoPlacement(ctx context.Context, username, profile string) ([]byte, string, model.ShardNode, error) {
	sh, err := s.chooseShardForUser(ctx, username)
	if err != nil {
		return nil, "", model.ShardNode{}, err
	}
	bundle, serial, err := s.pki.IssueBundleForTarget(username, profile, sh.ClientPublicURL, sh.ServerName)
	if err != nil {
		return nil, "", model.ShardNode{}, err
	}
	if err := s.updatePlacement(ctx, username, sh); err != nil {
		return nil, "", model.ShardNode{}, err
	}
	return bundle, serial, sh, nil
}

func formatShardInfo(sh model.ShardNode) string {
	return fmt.Sprintf("%s %s", sh.Name, sh.ClientPublicURL)
}

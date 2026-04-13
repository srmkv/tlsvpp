package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"tlsctrl-agent/internal/model"
)

func (s *Service) shardsPath() string {
	if s.pki == nil || strings.TrimSpace(s.pki.DataDir) == "" {
		return filepath.Join(".", "agent-data", "shards.json")
	}
	return filepath.Join(s.pki.DataDir, "shards.json")
}

func (s *Service) shardPlacementsPath() string {
	if s.pki == nil || strings.TrimSpace(s.pki.DataDir) == "" {
		return filepath.Join(".", "agent-data", "shard_placements.json")
	}
	return filepath.Join(s.pki.DataDir, "shard_placements.json")
}

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
	name := "local"
	url := strings.TrimSpace(settings.ClientPublicURL)
	serverName := strings.TrimSpace(settings.ServerName)
	if url == "" && s.pki != nil {
		url = strings.TrimSpace(s.pki.ClientURL)
	}
	if serverName == "" && s.pki != nil {
		serverName = strings.TrimSpace(s.pki.ServerName)
	}
	return normalizeShardNode(model.ShardNode{
		Name:            name,
		ClientPublicURL: url,
		ServerName:      serverName,
		Enabled:         true,
		Weight:          1,
		UpdatedAt:       time.Now().UTC(),
	})
}

func (s *Service) loadShards() ([]model.ShardNode, error) {
	path := s.shardsPath()
	if err := ensureDir(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		local := s.implicitLocalShard()
		_ = s.saveShards([]model.ShardNode{local})
		return []model.ShardNode{local}, nil
	}
	if err != nil {
		return nil, err
	}
	var out []model.ShardNode
	if len(raw) != 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		local := s.implicitLocalShard()
		_ = s.saveShards([]model.ShardNode{local})
		return []model.ShardNode{local}, nil
	}
	for i := range out {
		out[i] = normalizeShardNode(out[i])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Service) saveShards(shards []model.ShardNode) error {
	path := s.shardsPath()
	if err := ensureDir(path); err != nil {
		return err
	}
	for i := range shards {
		shards[i] = normalizeShardNode(shards[i])
	}
	b, err := json.MarshalIndent(shards, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func (s *Service) loadShardPlacements() (map[string]model.ShardPlacement, error) {
	path := s.shardPlacementsPath()
	if err := ensureDir(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]model.ShardPlacement{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]model.ShardPlacement{}
	if len(raw) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = map[string]model.ShardPlacement{}
	}
	return out, nil
}

func (s *Service) saveShardPlacements(m map[string]model.ShardPlacement) error {
	path := s.shardPlacementsPath()
	if err := ensureDir(path); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func (s *Service) Shards(ctx context.Context) ([]model.ShardNodeView, error) {
	shards, err := s.loadShards()
	if err != nil {
		return nil, err
	}
	placements, _ := s.loadShardPlacements()
	sessions, _ := s.backend.ListSessions(ctx)
	assigned := map[string]int{}
	connected := map[string]int{}
	for _, p := range placements {
		assigned[p.ShardName]++
	}
	for _, sess := range sessions {
		if !sess.Connected {
			continue
		}
		if p, ok := placements[sess.Username]; ok {
			connected[p.ShardName]++
		}
	}
	out := make([]model.ShardNodeView, 0, len(shards))
	for _, sh := range shards {
		out = append(out, model.ShardNodeView{
			ShardNode:       sh,
			AssignedUsers:   assigned[sh.Name],
			ConnectedUsers:  connected[sh.Name],
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

func (s *Service) UpsertShard(_ context.Context, n model.ShardNode) error {
	n = normalizeShardNode(n)
	if n.Name == "" {
		return errors.New("shard name is required")
	}
	if n.ClientPublicURL == "" {
		return errors.New("client_public_url is required")
	}
	shards, err := s.loadShards()
	if err != nil {
		return err
	}
	updated := false
	for i := range shards {
		if strings.EqualFold(shards[i].Name, n.Name) {
			shards[i] = n
			updated = true
			break
		}
	}
	if !updated {
		shards = append(shards, n)
	}
	return s.saveShards(shards)
}

func (s *Service) DeleteShard(_ context.Context, name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("shard name is required")
	}
	shards, err := s.loadShards()
	if err != nil {
		return err
	}
	out := make([]model.ShardNode, 0, len(shards))
	for _, sh := range shards {
		if !strings.EqualFold(sh.Name, name) {
			out = append(out, sh)
		}
	}
	if len(out) == 0 {
		return errors.New("cannot delete last shard")
	}
	if err := s.saveShards(out); err != nil {
		return err
	}
	placements, err := s.loadShardPlacements()
	if err == nil {
		for u, p := range placements {
			if strings.EqualFold(p.ShardName, name) {
				delete(placements, u)
			}
		}
		_ = s.saveShardPlacements(placements)
	}
	return nil
}

func (s *Service) chooseShardForUser(ctx context.Context, username string) (model.ShardNode, error) {
	shards, err := s.loadShards()
	if err != nil {
		return model.ShardNode{}, err
	}
	placements, err := s.loadShardPlacements()
	if err != nil {
		return model.ShardNode{}, err
	}
	if p, ok := placements[username]; ok {
		for _, sh := range shards {
			if strings.EqualFold(sh.Name, p.ShardName) && sh.Enabled && sh.ClientPublicURL != "" {
				return sh, nil
			}
		}
	}
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
	placements[username] = model.ShardPlacement{
		Username:        username,
		ShardName:       chosen.Name,
		ClientPublicURL: chosen.ClientPublicURL,
		ServerName:      chosen.ServerName,
		AssignedAt:      now,
		UpdatedAt:       now,
	}
	if err := s.saveShardPlacements(placements); err != nil {
		return model.ShardNode{}, err
	}
	_ = ctx
	return chosen, nil
}

func (s *Service) placementForUser(username string) (model.ShardPlacement, bool) {
	placements, err := s.loadShardPlacements()
	if err != nil {
		return model.ShardPlacement{}, false
	}
	p, ok := placements[username]
	return p, ok
}

func (s *Service) shardSummary(ctx context.Context) map[string]any {
	views, err := s.Shards(ctx)
	if err != nil {
		return map[string]any{"count": 0}
	}
	enabled := 0
	assigned := 0
	connected := 0
	for _, v := range views {
		if v.Enabled {
			enabled++
		}
		assigned += v.AssignedUsers
		connected += v.ConnectedUsers
	}
	return map[string]any{
		"count":           len(views),
		"enabled":         enabled,
		"assigned_users":  assigned,
		"connected_users": connected,
		"nodes":           views,
	}
}

func (s *Service) BundlePlacement(ctx context.Context, username string) (map[string]any, error) {
	sh, err := s.chooseShardForUser(ctx, strings.TrimSpace(username))
	if err != nil {
		return nil, err
	}
	p, _ := s.placementForUser(strings.TrimSpace(username))
	return map[string]any{
		"username":          username,
		"client_public_url": sh.ClientPublicURL,
		"server_name":       sh.ServerName,
		"assigned_shard":    sh.Name,
		"placement":         p,
	}, nil
}

func (s *Service) updatePlacement(username string, sh model.ShardNode) error {
	placements, err := s.loadShardPlacements()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	old := placements[username]
	assignedAt := old.AssignedAt
	if assignedAt.IsZero() || !strings.EqualFold(old.ShardName, sh.Name) {
		assignedAt = now
	}
	placements[username] = model.ShardPlacement{
		Username:        username,
		ShardName:       sh.Name,
		ClientPublicURL: sh.ClientPublicURL,
		ServerName:      sh.ServerName,
		AssignedAt:      assignedAt,
		UpdatedAt:       now,
	}
	return s.saveShardPlacements(placements)
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
	if err := s.updatePlacement(username, sh); err != nil {
		return nil, "", model.ShardNode{}, err
	}
	return bundle, serial, sh, nil
}

func (s *Service) deletePlacement(username string) {
	placements, err := s.loadShardPlacements()
	if err != nil {
		return
	}
	delete(placements, username)
	_ = s.saveShardPlacements(placements)
}

func (s *Service) reissueBundleWithAutoPlacement(ctx context.Context, username, profile string) ([]byte, string, model.ShardNode, error) {
	return s.issueBundleWithAutoPlacement(ctx, username, profile)
}

func formatShardInfo(sh model.ShardNode) string {
	return fmt.Sprintf("%s %s", sh.Name, sh.ClientPublicURL)
}

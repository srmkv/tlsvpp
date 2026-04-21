package freeradius_files

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"radius-agent/internal/model"
)

// contentHash computes a stable hash over users+groups (excluding CreatedAt).
func contentHash(snap *model.Snapshot) (string, error) {
	type stable struct {
		SourceID string                        `json:"source_id"`
		Users    map[string]*model.RadiusUser  `json:"users"`
		Groups   map[string]*model.RadiusGroup `json:"groups"`
	}
	b, err := json.Marshal(stable{SourceID: snap.SourceID, Users: snap.Users, Groups: snap.Groups})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

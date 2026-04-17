package model

import "time"

type Snapshot struct {
	SourceID    string                  `json:"source_id"`
	Revision    string                  `json:"revision"`
	CreatedAt   time.Time               `json:"created_at"`
	Users       map[string]*RadiusUser  `json:"users"`
	Groups      map[string]*RadiusGroup `json:"groups"`
	Diagnostics SnapshotDiagnostics     `json:"diagnostics"`
}

type SnapshotDiagnostics struct {
	UserCount  int    `json:"user_count"`
	GroupCount int    `json:"group_count"`
	Hash       string `json:"hash"`
}

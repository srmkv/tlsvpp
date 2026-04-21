package model

import "time"

type SourceType string

const (
	SourceFreeRadiusSQL   SourceType = "freeradius_sql"
	SourceFreeRadiusFiles SourceType = "freeradius_files"
)

type Source struct {
	ID          string        `json:"id" yaml:"id"`
	Name        string        `json:"name" yaml:"name"`
	Type        SourceType    `json:"type" yaml:"type"`
	Enabled     bool          `json:"enabled" yaml:"enabled"`
	DSN         string        `json:"dsn" yaml:"dsn"`
	SyncEvery   time.Duration `json:"-" yaml:"-"`
	Description string        `json:"description" yaml:"description"`
}

type SourceInput struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Enabled      bool   `json:"enabled"`
	DSN          string `json:"dsn"`
	SyncEverySec int    `json:"sync_every_sec"`
	Description  string `json:"description"`
}

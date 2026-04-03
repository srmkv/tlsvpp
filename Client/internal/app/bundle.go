package app

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"tlsclientnative/internal/state"

	"fyne.io/fyne/v2"
)

func importBundleReader(r fyne.URIReadCloser, cfg state.Config) (state.Config, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return cfg, fmt.Errorf("read configuration: %w", err)
	}
	return importBundle(data, cfg)
}

func importBundle(zipData []byte, cfg state.Config) (state.Config, error) {
	reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return cfg, fmt.Errorf("open zip: %w", err)
	}
	var caFile, crtFile, keyFile, metaFile *zip.File
	for _, f := range reader.File {
		name := strings.ToLower(filepath.Base(f.Name))
		switch name {
		case "ca.pem", "ca.crt", "ca.cer":
			if caFile == nil {
				caFile = f
			}
		case "client.crt", "client.pem", "client-cert.pem":
			if crtFile == nil {
				crtFile = f
			}
		case "client.key", "client-key.pem", "client.pem.key":
			if keyFile == nil {
				keyFile = f
			}
		case "metadata.json", "bundle.json":
			if metaFile == nil {
				metaFile = f
			}
		}
	}
	if caFile == nil || crtFile == nil || keyFile == nil {
		return cfg, fmt.Errorf("в ZIP не найдены обязательные файлы: ca.pem/ca.crt, client.crt/client.pem, client.key")
	}
	if err := writeZipFile(caFile, cfg.CACertFile, 0o600); err != nil {
		return cfg, err
	}
	if err := writeZipFile(crtFile, cfg.ClientCertFile, 0o600); err != nil {
		return cfg, err
	}
	if err := writeZipFile(keyFile, cfg.ClientKeyFile, 0o600); err != nil {
		return cfg, err
	}
	if metaFile != nil {
		rc, err := metaFile.Open()
		if err != nil {
			return cfg, fmt.Errorf("open metadata: %w", err)
		}
		defer rc.Close()
		var meta struct {
			Username   string `json:"username"`
			Profile    string `json:"profile"`
			ServerURL  string `json:"server_url"`
			ServerName string `json:"server_name"`
		}
		if err := json.NewDecoder(rc).Decode(&meta); err == nil {
			if meta.Username != "" {
				cfg.Username = meta.Username
			}
			if meta.Profile != "" {
				cfg.Profile = meta.Profile
			}
			if meta.ServerURL != "" {
				cfg.ServerURL = meta.ServerURL
			}
			if meta.ServerName != "" {
				cfg.ServerName = meta.ServerName
			}
		}
	}
	if err := state.Save(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func writeZipFile(zf *zip.File, dst string, mode os.FileMode) error {
	rc, err := zf.Open()
	if err != nil {
		return fmt.Errorf("open zip entry: %w", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return fmt.Errorf("read zip entry: %w", err)
	}
	if err := os.WriteFile(dst, data, mode); err != nil {
		return fmt.Errorf("write file %s: %w", dst, err)
	}
	return nil
}

type storageZipFilter struct{}

func (storageZipFilter) Matches(uri fyne.URI) bool {
	return strings.HasSuffix(strings.ToLower(uri.Name()), ".zip")
}
func (storageZipFilter) Name() string { return "ZIP files" }

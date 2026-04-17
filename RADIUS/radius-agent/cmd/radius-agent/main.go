package main

import (
	"log"
	"os"

	"radius-agent/internal/app"
	"radius-agent/internal/config"
)

func main() {
	cfgPath := os.Getenv("RADIUS_AGENT_CONFIG")
	if cfgPath == "" {
		cfgPath = "configs/radius-agent.example.yaml"
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	application, err := app.New(cfg)
	if err != nil {
		log.Fatalf("build app: %v", err)
	}
	if err := application.Run(); err != nil {
		log.Fatalf("run app: %v", err)
	}
}

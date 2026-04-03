package main

import (
	"log"

	"tlsclientnative/internal/app"
)

func main() {
	if err := app.Run(); err != nil {
		log.Fatalf("client failed: %v", err)
	}
}

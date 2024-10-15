package main

import (
	"log"
	"os"

	"github.com/crema-labs/sxg-go/internal/server"
)

func main() {
	priv_key, ok := os.LookupEnv("PRIVATE_KEY")
	if !ok {
		log.Fatal("PRIVATE_KEY environment variable is required")
	}

	// Create a new server
	srv := server.NewServer(priv_key)
	if err := srv.Run(":8080"); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}

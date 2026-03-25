package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/vedetta-network/vedetta/backend/internal/api"
)

func main() {
	port := os.Getenv("VEDETTA_PORT")
	if port == "" {
		port = "8080"
	}

	router := api.NewRouter()

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("Vedetta backend starting on :%s", port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}

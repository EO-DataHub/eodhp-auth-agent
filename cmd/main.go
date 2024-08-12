package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/authorize", authorizeHandler)

	fmt.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Could not start server: %s\n", err.Error())
	}
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	// Handle authentication requests
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Authentication endpoint"))
}

func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	// Handle authorization requests
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Authorization endpoint"))
}

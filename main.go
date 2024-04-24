package main

import (
	"log"
	"net/http"
	"unstoppable-go/handlers"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", handlers.InitUnstoppable)
	mux.HandleFunc("/", handlers.UnstoppableCallBack)
	server := http.Server{
		Handler: mux,
		Addr:    ":3000",
	}
	if err :=server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

package main

import (
	"github.com/YeandAmen/underdog/internal/config"
	"github.com/YeandAmen/underdog/internal/server"
	"log"
	"net/http"
	"time"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	app, err := server.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer app.Store.Close()
	host := &http.Server{Addr: cfg.Addr, Handler: app.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}
	log.Printf("Underdog listening on %s", cfg.Addr)
	log.Fatal(host.ListenAndServe())
}

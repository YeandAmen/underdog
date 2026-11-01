package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/YeandAmen/identityshield/internal/analyst"
	"github.com/YeandAmen/identityshield/internal/config"
	"github.com/YeandAmen/identityshield/internal/datasets"
	"github.com/YeandAmen/identityshield/internal/lab"
	"github.com/YeandAmen/identityshield/internal/server"
)

func main() {
	if err := run(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run() error {
	command := "serve"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command, args = args[0], args[1:]
	}
	if command == "help" || command == "--help" {
		fmt.Println("IdentityShield — identity-aware cyber defence\n\nCommands:\n  serve      Start the embedded web workspace\n  doctor     Validate configuration (--check-ai probes the provider)\n  simulate   Write labelled lab scenario events to stdout\n  snapshot   Write the synthetic AD policy fixture to stdout\n  import     Import evidence into a running local workspace\n\nRun a command with -help for flags.")
		return nil
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	switch command {
	case "doctor":
		flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
		check := flags.Bool("check-ai", false, "Probe the configured model with a small request")
		if err := flags.Parse(args); err != nil {
			return err
		}
		fmt.Printf("Go workspace: ready\nListen: %s\nStorage: %s\nAI provider: %s\nAI model: %s\nAgent Router credential present: %t\nKaggle credential present: %t\nSynthetic starter data: %t\n", cfg.Addr, cfg.DataDir, cfg.AIProvider, cfg.AIModel, cfg.AIKey != "", cfg.KaggleToken != "" || cfg.KaggleUsername != "" && cfg.KaggleKey != "", cfg.Demo)
		if *check {
			ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
			defer cancel()
			if err := analyst.New(cfg).Check(ctx); err != nil {
				return err
			}
			fmt.Println("Model endpoint: connected")
		}
		return nil
	case "simulate":
		flags := flag.NewFlagSet("simulate", flag.ContinueOnError)
		scenario := flags.String("scenario", "identity-to-ot", "Scenario: "+strings.Join(lab.ScenarioNames(), ", "))
		baseline := flags.Bool("baseline", false, "Write the full labelled benchmark corpus")
		if err := flags.Parse(args); err != nil {
			return err
		}
		events := lab.Scenario(*scenario, fmt.Sprintf("cli-%d", time.Now().UnixNano()), time.Now())
		if *baseline {
			events = lab.Baseline(time.Now())
		}
		if len(events) == 0 {
			return fmt.Errorf("unknown scenario %q", *scenario)
		}
		encoder := json.NewEncoder(os.Stdout)
		for _, event := range events {
			if err := encoder.Encode(event); err != nil {
				return err
			}
		}
		return nil
	case "snapshot":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(lab.Snapshot(time.Now()))
	case "tank":
		flags := flag.NewFlagSet("tank", flag.ContinueOnError)
		samples := flags.Int("samples", 120, "Number of five-second process samples")
		attackAfter := flags.Int("attack-after", -1, "Manipulate inlet/outlet after this sample; -1 is normal-only")
		seed := flags.Uint64("seed", 42, "Reproducible simulator seed")
		if err := flags.Parse(args); err != nil {
			return err
		}
		if *samples < 1 || *samples > 200000 || *attackAfter < -1 {
			return fmt.Errorf("samples must be 1..200000 and attack-after must be -1 or greater")
		}
		encoder := json.NewEncoder(os.Stdout)
		for _, event := range lab.TankEvents(*samples, *attackAfter, *seed, time.Now()) {
			if err := encoder.Encode(event); err != nil {
				return err
			}
		}
		return nil
	case "import":
		return importFile(cfg, args)
	case "serve":
		flags := flag.NewFlagSet("serve", flag.ContinueOnError)
		addr := flags.String("addr", cfg.Addr, "Listen address")
		if err := flags.Parse(args); err != nil {
			return err
		}
		if *addr != cfg.Addr {
			return fmt.Errorf("set IDENTITYSHIELD_ADDR in the environment to change the validated listen address")
		}
		app, err := server.New(cfg)
		if err != nil {
			return err
		}
		defer app.Store.Close()
		httpServer := &http.Server{Addr: cfg.Addr, Handler: app.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		go func() {
			<-ctx.Done()
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			httpServer.Shutdown(shutdown)
		}()
		slog.Info("IdentityShield is ready", "url", "http://"+cfg.Addr, "ai", cfg.AIProvider, "model", cfg.AIModel)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unknown command %q; run identityshield help", command)
	}
}

func importFile(cfg config.Config, args []string) error {
	flags := flag.NewFlagSet("import", flag.ContinueOnError)
	file := flags.String("file", "", "Evidence file (JSONL, CSV, GZ, ZIP)")
	format := flags.String("format", "canonical", "Adapter: canonical, windows-jsonl, lanl-auth, hai-csv")
	source := flags.String("source", "user-import", "Publisher/source identifier")
	maxEvents := flags.Int("max-events", 20000, "Maximum LANL rows to stream from a large original file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *file == "" {
		return fmt.Errorf("-file is required")
	}
	f, err := os.Open(*file)
	if err != nil {
		return err
	}
	defer f.Close()
	var data []byte
	if *format == "lanl-auth" {
		if *maxEvents <= 0 || *maxEvents > 200000 {
			return fmt.Errorf("max-events must be between 1 and 200000")
		}
		data, err = datasets.SliceLANL(f, *maxEvents)
	} else {
		data, err = io.ReadAll(io.LimitReader(f, datasets.MaxPayloadBytes+1))
	}
	if err != nil {
		return err
	}
	if len(data) > datasets.MaxPayloadBytes {
		return fmt.Errorf("payload exceeds 64 MiB; prepare a bounded slice")
	}
	// Send to the running app, so all writes use its validation and provenance path.
	return upload(cfg, filepath.Base(*file), *format, *source, data)
}

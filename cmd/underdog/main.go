package main

import (
	"log/slog"
	"os"

	"github.com/YeandAmen/underdog/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:]); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

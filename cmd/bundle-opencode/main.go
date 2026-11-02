package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/YeandAmen/underdog/internal/opencodecli"
)

func main() {
	if err := bundle(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func bundle() error {
	root, err := opencodecli.ProjectRoot()
	if err != nil {
		return err
	}
	binary, err := opencodecli.LocalBinary(root)
	if err != nil {
		return err
	}
	source, err := os.Open(binary)
	if err != nil {
		return err
	}
	defer source.Close()
	path := filepath.Join(root, "internal", "opencodecli", "assets", "opencode.gz")
	target, err := os.Create(path)
	if err != nil {
		return err
	}
	writer := gzip.NewWriter(target)
	if _, err := io.Copy(writer, source); err != nil {
		writer.Close()
		target.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		target.Close()
		return err
	}
	if err := target.Close(); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	fmt.Printf("Bundled OpenCode %s: %d compressed bytes\n", opencodecli.Version, info.Size())
	return nil
}

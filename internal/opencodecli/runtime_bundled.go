//go:build opencode_bundle

package opencodecli

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"io"
	"os"
	"path/filepath"
	"sync"
)

//go:embed assets/opencode.gz
var bundled []byte

var extraction sync.Mutex

func bundledBinary(dir string) (string, error) {
	extraction.Lock()
	defer extraction.Unlock()
	path := filepath.Join(dir, "opencode-"+Version)
	if regularFile(path) {
		return path, nil
	}
	reader, err := gzip.NewReader(bytes.NewReader(bundled))
	if err != nil {
		return "", err
	}
	defer reader.Close()
	file, err := os.CreateTemp(dir, "engine-")
	if err != nil {
		return "", err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if _, err := io.Copy(file, reader); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Chmod(0700); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temp, path); err != nil {
		return "", err
	}
	return path, nil
}

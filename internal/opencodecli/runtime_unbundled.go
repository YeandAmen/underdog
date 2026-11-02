//go:build !opencode_bundle

package opencodecli

import "errors"

func bundledBinary(string) (string, error) {
	return "", errors.New("OpenCode was not included in this build")
}

package cli

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"time"

	"github.com/YeandAmen/underdog/internal/config"
)

func upload(cfg config.Config, filename, format, source string, data []byte) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	file, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	for key, value := range map[string]string{"format": format, "source": source, "name": filename} {
		if err := writer.WriteField(key, value); err != nil {
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, "http://"+cfg.Addr+"/api/datasets/import", &body)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	if cfg.AccessToken != "" {
		request.Header.Set("Authorization", "Bearer "+cfg.AccessToken)
	}
	response, err := (&http.Client{Timeout: 120 * time.Second}).Do(request)
	if err != nil {
		return fmt.Errorf("start the Underdog server before importing: %w", err)
	}
	defer response.Body.Close()
	result, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusCreated {
		return fmt.Errorf("import failed (HTTP %d): %s", response.StatusCode, result)
	}
	_, err = os.Stdout.Write(result)
	return err
}

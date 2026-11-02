package config

import (
	"bufio"
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Addr           string
	DataDir        string
	Demo           bool
	AccessToken    string
	PublicAccess   bool
	AIProvider     string
	AIBackend      string
	AIModel        string
	AIBaseURL      string
	AIKey          string
	KaggleToken    string
	KaggleUsername string
	KaggleKey      string
	DatabaseURL    string
	Hosted         bool
	OpenCodeBinary string
	WorkerToken    string
	WorkerURL      string
}

func Load() (Config, error) {
	values := map[string]string{}
	f, err := os.Open(".env")
	if err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(strings.TrimPrefix(line, "export "), "=")
			if ok {
				values[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), "\"'")
			}
		}
		if err := scanner.Err(); err != nil {
			return Config{}, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Config{}, err
	}
	get := func(key, fallback string) string {
		if v, ok := os.LookupEnv(key); ok {
			return v
		}
		if v, ok := values[key]; ok {
			return v
		}
		return fallback
	}
	demo, err := strconv.ParseBool(get("IDENTITYSHIELD_DEMO", "true"))
	if err != nil {
		return Config{}, errors.New("IDENTITYSHIELD_DEMO must be true or false")
	}
	publicAccess, err := strconv.ParseBool(get("IDENTITYSHIELD_PUBLIC_ACCESS", "false"))
	if err != nil {
		return Config{}, errors.New("IDENTITYSHIELD_PUBLIC_ACCESS must be true or false")
	}
	c := Config{
		Addr:           get("IDENTITYSHIELD_ADDR", "127.0.0.1:8787"),
		DataDir:        get("IDENTITYSHIELD_DATA_DIR", "./data"),
		Demo:           demo,
		AccessToken:    get("IDENTITYSHIELD_ACCESS_TOKEN", ""),
		PublicAccess:   publicAccess,
		AIProvider:     get("IDENTITYSHIELD_AI_PROVIDER", "agentrouter"),
		AIBackend:      get("UNDERDOG_AI_BACKEND", "direct"),
		AIModel:        get("IDENTITYSHIELD_AI_MODEL", "gpt-6.1-sol"),
		AIBaseURL:      get("IDENTITYSHIELD_AI_BASE_URL", get("AGENT_ROUTER_BASE_URL", "https://agentrouter.org/v1")),
		AIKey:          get("AGENT_ROUTER_API_KEY", get("AGENTROUTER_API_KEY", "")),
		KaggleToken:    get("KAGGLE_API_TOKEN", ""),
		KaggleUsername: get("KAGGLE_USERNAME", ""),
		KaggleKey:      get("KAGGLE_KEY", ""),
		DatabaseURL:    get("DATABASE_URL", ""),
		Hosted:         get("VERCEL", "") == "1",
		OpenCodeBinary: get("UNDERDOG_OPENCODE_BINARY", ""),
		WorkerToken:    get("UNDERDOG_WORKER_TOKEN", ""),
		WorkerURL:      get("UNDERDOG_WORKSPACE_URL", "https://underdog-fyield1.vercel.app"),
	}
	if c.Hosted {
		c.DataDir = "/tmp/identityshield"
		c.Addr = ":" + get("PORT", "3000")
		if c.DatabaseURL == "" {
			return Config{}, errors.New("DATABASE_URL is required for durable Vercel storage")
		}
	}
	if c.AIProvider != "agentrouter" && c.AIProvider != "openrouter" && c.AIProvider != "ollama" && c.AIProvider != "local" {
		return Config{}, errors.New("AI provider must be agentrouter, openrouter, ollama, or local")
	}
	if c.AIBackend != "direct" && c.AIBackend != "opencode" && c.AIBackend != "worker" {
		return Config{}, errors.New("UNDERDOG_AI_BACKEND must be direct, opencode, or worker")
	}
	if c.AIBackend == "worker" && c.WorkerToken == "" {
		return Config{}, errors.New("UNDERDOG_WORKER_TOKEN is required for the report worker")
	}
	if c.AIProvider == "openrouter" {
		c.AIBaseURL = get("IDENTITYSHIELD_AI_BASE_URL", get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"))
		c.AIModel = get("IDENTITYSHIELD_AI_MODEL", "openai/gpt-6.1-sol")
		c.AIKey = get("OPENROUTER_API_KEY", get("IDENTITYSHIELD_AI_API_KEY", c.AIKey))
	}
	if c.AIProvider == "ollama" {
		c.AIBaseURL = get("IDENTITYSHIELD_AI_BASE_URL", "http://127.0.0.1:11434/v1")
		c.AIModel = get("IDENTITYSHIELD_AI_MODEL", "qwen3:8b")
	}
	u, err := url.Parse(c.AIBaseURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return Config{}, errors.New("AI base URL must be an absolute HTTP(S) URL without credentials or query parameters")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback())) {
		return Config{}, errors.New("AI endpoint requires HTTPS, except for a loopback local provider")
	}
	host, _, err := net.SplitHostPort(c.Addr)
	if err != nil {
		return Config{}, errors.New("listen address must use host:port")
	}
	if host != "localhost" && !net.ParseIP(host).IsLoopback() && c.AccessToken == "" && !c.PublicAccess {
		return Config{}, errors.New("set IDENTITYSHIELD_ACCESS_TOKEN when listening outside loopback")
	}
	return c, nil
}

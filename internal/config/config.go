package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type AppConfig struct {
	Port        int      `json:"port"`
	DNSPort     int      `json:"dns_port"`
	Domain      string   `json:"domain"`
	DB          string   `json:"db"`
	PublicIP    string   `json:"public_ip"`
	Bind        string   `json:"bind"`
	AdminEmails []string `json:"admin_emails"`
}

func Defaults() *AppConfig {
	home, _ := os.UserHomeDir()
	return &AppConfig{
		Port:        8080,
		DNSPort:     5300,
		Domain:      "redir.local",
		DB:          filepath.Join(home, ".redir", "redir.db"),
		PublicIP:    "",
		Bind:        "0.0.0.0",
		AdminEmails: []string{},
	}
}

func DefaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".redir", "config.json")
}

// Load reads the config file at path. If the file does not exist it is created
// with defaults. Returns the merged config.
func Load(path string) (*AppConfig, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, save(path, cfg)
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func save(path string, cfg *AppConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

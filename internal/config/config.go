package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type AppConfig struct {
	Port        int      `yaml:"port"`
	DNSPort     int      `yaml:"dns_port"`
	Domain      string   `yaml:"domain"`
	DB          string   `yaml:"db"`
	PublicIP    string   `yaml:"public_ip"`
	Bind        string   `yaml:"bind"`
	AdminEmails []string `yaml:"admin_emails"`
}

func Defaults() *AppConfig {
	home, _ := os.UserHomeDir()
	return &AppConfig{
		Port:        9999,
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
	return filepath.Join(home, ".redir", "config.yaml")
}

// Load reads the config file at path. If the file does not exist it is created
// with defaults on first run.
func Load(path string) (*AppConfig, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, save(path, cfg)
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func save(path string, cfg *AppConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

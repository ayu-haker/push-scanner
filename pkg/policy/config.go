package policy

import (
	"os"

	"gopkg.in/yaml.v3"

	"push-scanner/pkg/scanner"
)

// Config describes .push-scanner.yml configuration file format for enterprise v0.3.
type Config struct {
	Team            string   `yaml:"team"`             // e.g. "platform-sec", "core-dev"
	EnvironmentRing string   `yaml:"environment_ring"` // "prod", "staging", "dev"
	WebhookURL      string   `yaml:"webhook_url"`
	BaselinePath    string   `yaml:"baseline_path"`
	PolicyMode      string   `yaml:"mode"` // "default", "strict", "permissive"
	FailOnSeverity  string   `yaml:"fail_on"`
	StrictAIMode    bool     `yaml:"strict_ai"`
	IgnorePaths     []string `yaml:"ignore_paths"`
	IgnoreRules     []string `yaml:"ignore_rules"`
	CustomRules     []struct {
		ID       string           `yaml:"id"`
		Pattern  string           `yaml:"pattern"`
		Severity scanner.Severity `yaml:"severity"`
	} `yaml:"custom_rules"`
}

func DefaultConfig() Config {
	return Config{
		Team:            "default",
		EnvironmentRing: "dev",
		PolicyMode:      "default",
		FailOnSeverity:  "HIGH",
		StrictAIMode:    false,
		IgnorePaths: []string{
			"node_modules/**",
			".git/**",
			"vendor/**",
		},
		IgnoreRules: []string{},
	}
}

func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	err = yaml.Unmarshal(data, &cfg)
	return cfg, err
}

package internal

import (
	"encoding/json"
	"fmt"
	"strings"
)

type PluginConfig struct {
	Regions      []string
	PolicyLabels map[string]string
}

func ParseConfig(raw map[string]string) (*PluginConfig, error) {
	config := &PluginConfig{}

	if v := strings.TrimSpace(raw["regions"]); v != "" {
		for _, r := range strings.Split(v, ",") {
			if r := strings.TrimSpace(r); r != "" {
				config.Regions = append(config.Regions, r)
			}
		}
	}
	if len(config.Regions) == 0 {
		return nil, fmt.Errorf("config key 'regions' is required")
	}

	if v := strings.TrimSpace(raw["policy_labels"]); v != "" {
		if err := json.Unmarshal([]byte(v), &config.PolicyLabels); err != nil {
			return nil, fmt.Errorf("could not parse policy_labels: %w", err)
		}
	}

	return config, nil
}

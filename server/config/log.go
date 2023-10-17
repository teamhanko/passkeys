package config

type Logger struct {
	LogHealthAndMetrics bool `yaml:"log_health_and_metrics,omitempty" json:"log_health_and_metrics" koanf:"log_health_and_metrics" jsonschema:"default=true"`
}

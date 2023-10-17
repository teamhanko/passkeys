package config

type AuditLog struct {
	ConsoleOutput AuditLogConsole `yaml:"console_output" json:"console_output,omitempty" koanf:"console_output" split_words:"true"`
	Storage       AuditLogStorage `yaml:"storage" json:"storage,omitempty" koanf:"storage"`
}

type AuditLogStorage struct {
	Enabled bool `yaml:"enabled" json:"enabled,omitempty" koanf:"enabled" jsonschema:"default=false"`
}

type AuditLogConsole struct {
	Enabled      bool         `yaml:"enabled" json:"enabled,omitempty" koanf:"enabled" jsonschema:"default=true"`
	OutputStream OutputStream `yaml:"output" json:"output,omitempty" koanf:"output" split_words:"true" jsonschema:"default=stdout,enum=stdout,enum=stderr"`
}

var (
	OutputStreamStdOut OutputStream = "stdout"
	OutputStreamStdErr OutputStream = "stderr"
)

type OutputStream string

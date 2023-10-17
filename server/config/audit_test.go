package config

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseValidAuditLogConfig(t *testing.T) {
	configPath := "./testdata/audit-config.yaml"
	auditConfig, err := loadTestConfig[AuditLog](&configPath)
	if err != nil {
		t.Error(err)
	}

	assert.NotNil(t, auditConfig)
	assert.NotNil(t, auditConfig.ConsoleOutput)
	assert.NotNil(t, auditConfig.Storage)
	assert.True(t, auditConfig.ConsoleOutput.Enabled)
	assert.Equal(t, OutputStreamStdOut, auditConfig.ConsoleOutput.OutputStream)
	assert.True(t, auditConfig.Storage.Enabled)
}

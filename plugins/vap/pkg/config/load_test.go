package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_ParsesFileAndDurations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	content := `
server:
  port: 9443
webhook:
  workers: 8
reconcile:
  interval: 10m
  orphanTTL: 24h
report:
  labels:
    team: platform
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	cfg, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, 9443, cfg.Server.Port)
	assert.Equal(t, 8, cfg.Webhook.Workers)
	assert.Equal(t, 10*time.Minute, cfg.Reconcile.Interval)
	assert.Equal(t, 24*time.Hour, cfg.Reconcile.OrphanTTL)
	assert.Equal(t, "platform", cfg.Report.Labels["team"])
	// Unset fields fall back to Default().
	assert.Equal(t, "vap-plugin", cfg.LeaderElection.LeaseName)
	assert.False(t, cfg.Report.ReportDenied, "expected report.reportDenied to default to false when unset")
}

func TestLoad_ServerAndAPIDefaultToEnabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("logging:\n  level: debug\n"), 0o600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.True(t, cfg.Server.Enabled, "expected server.enabled to default to true when unset")
	assert.True(t, cfg.API.Enabled, "expected api.enabled to default to true when unset")
}

func TestLoad_ServerAndAPICanBeDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("server:\n  enabled: false\napi:\n  enabled: false\n"), 0o600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.False(t, cfg.Server.Enabled)
	assert.False(t, cfg.API.Enabled)
}

func TestLoad_ReportDeniedCanBeEnabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("report:\n  reportDenied: true\n"), 0o600))

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.True(t, cfg.Report.ReportDenied)
}

func TestLoad_ExplicitMissingFileIsAnError(t *testing.T) {
	// An explicit --config path that doesn't exist is almost certainly an
	// operator typo, so it should fail loudly rather than silently fall
	// back to defaults.
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	assert.Error(t, err, "expected an error for an explicit missing config path")
}

func TestLoad_NoPathFallsBackToDefaultsWhenNoLocalConfigFile(t *testing.T) {
	dir := t.TempDir()
	wd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(wd) })

	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, Default().Server.Port, cfg.Server.Port)
}

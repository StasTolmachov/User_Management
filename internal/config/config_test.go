package config

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"foxminded/4_user_management/slogger"
)

func TestLoad(t *testing.T) {
	slogger.MakeLogger(true)

	t.Run("Success: Load valid config", func(t *testing.T) {

		t.Setenv("DB_HOST", "localhost")
		t.Setenv("DB_PORT", "5432")
		t.Setenv("DB_USER", "postgres")
		t.Setenv("DB_PASSWORD", "secret")
		t.Setenv("DB_NAME", "users_db")
		t.Setenv("DB_MIGRATE_PATH", "file://migrations")
		t.Setenv("API_PORT", "8080")

		cfg, err := Load()
		assert.NoError(t, err)
		assert.NotNil(t, cfg)
		assert.Equal(t, "localhost", cfg.DB.Host)
		assert.Equal(t, "disable", cfg.DB.SSLMode)
		assert.Equal(t, "8080", cfg.Api.Port)
	})
}

func TestDB_DSN(t *testing.T) {
	dbCfg := DB{
		Host:     "localhost",
		Port:     "5432",
		Username: "user",
		Password: "pass",
		Database: "mydb",
		SSLMode:  "disable",
	}

	expectedDSN := "postgres://user:pass@localhost:5432/mydb?sslmode=disable"
	assert.Equal(t, expectedDSN, dbCfg.DSN())
}

package config

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"

	"foxminded/4_user_management/slogger"
)

type Config struct {
	DB    DB
	Api   Api
	JWT   JWT
	Admin Admin
	Redis Redis
}

type Redis struct {
	Host string
	Port string
	TTL  time.Duration
}
type DB struct {
	Host        string
	Port        string
	Username    string
	Password    string
	Database    string
	SSLMode     string
	MigratePath string
}

type Api struct {
	Port string
}

type JWT struct {
	Secret string
	TTL    time.Duration
}

type Admin struct {
	Email    string
	Password string
}

func Load() (*Config, error) {
	cfg := &Config{}

	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found — using only system environment")
	}

	if cfg.DB.Host = os.Getenv("DB_HOST"); cfg.DB.Host == "" {
		return nil, fmt.Errorf("DB_HOST environment variable not set")
	}
	if cfg.DB.Port = os.Getenv("DB_PORT"); cfg.DB.Port == "" {
		return nil, fmt.Errorf("DB_PORT environment variable not set")
	}
	if cfg.DB.Username = os.Getenv("DB_USER"); cfg.DB.Username == "" {
		return nil, fmt.Errorf("DB_USER environment variable not set")
	}
	if cfg.DB.Password = os.Getenv("DB_PASSWORD"); cfg.DB.Password == "" {
		return nil, fmt.Errorf("DB_PASSWORD environment variable not set")
	}
	if cfg.DB.Database = os.Getenv("DB_NAME"); cfg.DB.Database == "" {
		return nil, fmt.Errorf("DB_NAME environment variable not set")
	}
	if cfg.DB.SSLMode = os.Getenv("DB_SSLMODE"); cfg.DB.SSLMode == "" {
		cfg.DB.SSLMode = "disable"
		slogger.Log.Warn("DB_SSLMODE environment variable not set. Using default:", "DB_SSLMODE", cfg.DB.SSLMode)
	}
	if cfg.DB.MigratePath = os.Getenv("DB_MIGRATE_PATH"); cfg.DB.MigratePath == "" {
		return nil, fmt.Errorf("DB_MIGRATE_PATH environment variable not set")
	}
	if cfg.Api.Port = os.Getenv("API_PORT"); cfg.Api.Port == "" {
		return nil, fmt.Errorf("API_PORT environment variable not set")
	}

	if cfg.JWT.Secret = os.Getenv("JWT_SECRET"); cfg.JWT.Secret == "" {
		return nil, fmt.Errorf("JWT_SECRET environment variable not set")
	}
	ttlString := os.Getenv("JWT_TTL")
	if ttlString == "" {
		cfg.JWT.TTL = time.Hour * 24
	} else {
		ttl, err := time.ParseDuration(ttlString)
		if err != nil {
			cfg.JWT.TTL = time.Hour * 24
			slogger.Log.Warn("invalid JWT_TTL format:", "err", err)
		}
		cfg.JWT.TTL = ttl
	}

	if cfg.Admin.Email = os.Getenv("ADMIN_EMAIL"); cfg.Admin.Email == "" {
		return nil, fmt.Errorf("ADMIN_EMAIL environment variable not set")
	}
	if cfg.Admin.Password = os.Getenv("ADMIN_PASSWORD"); cfg.Admin.Password == "" {
		return nil, fmt.Errorf("ADMIN_PASSWORD environment variable not set")
	}

	if cfg.Redis.Host = os.Getenv("REDIS_HOST"); cfg.Redis.Host == "" {
		cfg.Redis.Host = "localhost"
	}
	if cfg.Redis.Port = os.Getenv("REDIS_PORT"); cfg.Redis.Port == "" {
		cfg.Redis.Port = "6379"
	}
	redisTTLStr := os.Getenv("REDIS_TTL")
	if redisTTLStr == "" {
		cfg.Redis.TTL = time.Minute
	} else {
		ttl, err := time.ParseDuration(redisTTLStr)
		if err != nil {
			cfg.Redis.TTL = time.Minute
			slogger.Log.Warn("invalid REDIS_TTL format", "err", err)
		}
		cfg.Redis.TTL = ttl
	}

	return cfg, nil
}

func (d *DB) DSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		d.Username,
		d.Password,
		d.Host,
		d.Port,
		d.Database,
		d.SSLMode,
	)
}

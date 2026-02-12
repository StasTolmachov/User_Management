package repository

import (
	"fmt"
	"log"

	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jmoiron/sqlx"

	"foxminded/4_user_management/internal/config"
)

type Postgres struct {
	db *sqlx.DB
}

func NewPostgres(cfg config.DB) (*Postgres, error) {
	db, err := sqlx.Connect("postgres", cfg.DSN())
	if err != nil {
		return nil, err
	}
	p := &Postgres{db: db}

	if err := p.runMigrations(cfg.MigratePath); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}
	return p, nil
}

func (p *Postgres) Close() {
	err := p.db.Close()
	if err != nil {
		log.Fatal(err)
	}
}

func (p *Postgres) runMigrations(migratePath string) error {
	driver, err := postgres.WithInstance(p.db.DB, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("failed to create migration driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		migratePath,
		"postgres",
		driver,
	)
	if err != nil {
		return fmt.Errorf("failed to create migration instance: %w", err)
	}

	err = m.Up()
	if err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("migration failed: %w", err)
	}

	return nil
}

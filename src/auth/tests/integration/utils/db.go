package utils

import (
	"auth/internal/adapter/database"
	"auth/internal/config"

	"github.com/jmoiron/sqlx"
)

func NewTestDB() (*sqlx.DB, error) {
	cfg := config.PostgresConfig{
		Host:     "localhost",
		Port:     54322,
		User:     "postgres",
		Password: "password",
		DBName:   "auth_db",
		SSLMode:  "disable",
	}

	db, err := database.NewPostgresDB(cfg)

	if err != nil {
		cfg.Host = "docker"
		db, err = database.NewPostgresDB(cfg)
	}

	return db, err
}

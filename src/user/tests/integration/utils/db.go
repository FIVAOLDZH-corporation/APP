package utils

import (
	"user/internal/adapter/database"
	"user/internal/config"

	"github.com/jmoiron/sqlx"
)

func NewTestDB() (*sqlx.DB, error) {
	cfg := config.PostgresConfig{
		Host:     "localhost",
		Port:     54321,
		User:     "postgres",
		Password: "password",
		DBName:   "user_db",
		SSLMode:  "disable",
	}

	db, err := database.NewPostgresDB(cfg)

	if err != nil {
		cfg.Host = "docker"
		db, err = database.NewPostgresDB(cfg)
	}

	return db, err
}

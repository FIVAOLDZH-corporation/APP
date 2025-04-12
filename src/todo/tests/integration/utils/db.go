package utils

import (
	"todo/internal/adapter/database"
	"todo/internal/config"

	"github.com/jmoiron/sqlx"
)

func NewTestDB() (*sqlx.DB, error) {
	cfg := config.PostgresConfig{
		Host:     "localhost",
		Port:     54323,
		User:     "postgres",
		Password: "password",
		DBName:   "todo_db",
		SSLMode:  "disable",
	}

	db, err := database.NewPostgresDB(cfg)

	if err != nil {
		cfg.Host = "docker"
		db, err = database.NewPostgresDB(cfg)
	}

	return db, err
}

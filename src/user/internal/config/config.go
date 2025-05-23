package config

import (
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Log        LogConfig        `toml:"log"`
	Pagination PaginationConfig `toml:"pagination"`
	User       UserConfig       `toml:"user"`
}

type LogConfig struct {
	Path  string `toml:"path"`
	Level string `toml:"level"`
}

type PaginationConfig struct {
	Limit  int `toml:"limit"`
	Offset int `toml:"offset"`
}

type UserConfig struct {
	Path          string         `toml:"path"`
	ContainerName string         `toml:"container_name"`
	BaseURL       string         `toml:"base_url"`
	Database      string         `toml:"database"`
	LocalPort     int            `toml:"local_port"`
	ExposedPort   int            `toml:"exposed_port"`
	Log           LogConfig      `toml:"log"`
	Postgres      PostgresConfig `toml:"postgres"`
	Mongo         MongoConfig    `toml:"mongo"`
}

type PostgresConfig struct {
	Host     string `toml:"host"`
	Port     int    `toml:"port"`
	User     string `toml:"user"`
	Password string `toml:"password"`
	DBName   string `toml:"dbname"`
	SSLMode  string `toml:"sslmode"`
}

type MongoConfig struct {
	Host     string `toml:"host"`
	Port     int    `toml:"port"`
	User     string `toml:"user"`
	Password string `toml:"password"`
	DBName   string `toml:"dbname"`
}

func LoadConfig(configPath string) (*Config, error) {
	var config Config

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, err
	}

	if _, err := toml.DecodeFile(configPath, &config); err != nil {
		return nil, err
	}

	s := &config.User.Log
	s.Path = config.Log.Path + "/" + s.Path
	if s.Level == "" {
		s.Level = config.Log.Level
	}

	return &config, nil
}

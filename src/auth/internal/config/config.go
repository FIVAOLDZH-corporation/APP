package config

import (
	"os"

	"github.com/BurntSushi/toml"
)

type UsecaseConfig struct {
	SMTP  SMTPConfig  `toml:"smtp"`
	Cache CacheConfig `toml:"cache"`
}

type Config struct {
	Log        LogConfig        `toml:"log"`
	Pagination PaginationConfig `toml:"pagination"`
	User       UserConfig       `toml:"user"`
	Auth       AuthConfig       `toml:"auth"`
}

type SMTPConfig struct {
	Host     string `toml:"host"`
	Port     string `toml:"port"`
	Username string `toml:"username"`
	Password string `toml:"password"`
}

type CacheConfig struct {
	TTL int `toml:"ttl"`
}

type LogConfig struct {
	Path  string `toml:"path"`
	Level string `toml:"level"`
}

type PaginationConfig struct {
	Limit  int `toml:"limit"`
	Offset int `toml:"offset"`
}

type AggregatorConfig struct {
	Path          string    `toml:"path"`
	ContainerName string    `toml:"container_name"`
	BaseURL       string    `toml:"base_url"`
	LocalPort     int       `toml:"local_port"`
	ExposedPort   int       `toml:"exposed_port"`
	Log           LogConfig `toml:"log"`
}

type UserConfig struct {
	ContainerName string `toml:"container_name"`
	BaseURL       string `toml:"base_url"`
	LocalPort     int    `toml:"local_port"`
}

type AuthConfig struct {
	Path          string         `toml:"path"`
	ContainerName string         `toml:"container_name"`
	BaseURL       string         `toml:"base_url"`
	Database      string         `toml:"database"`
	LocalPort     int            `toml:"local_port"`
	ExposedPort   int            `toml:"exposed_port"`
	Log           LogConfig      `toml:"log"`
	Postgres      PostgresConfig `toml:"postgres"`
	Token         TokenConfig    `toml:"token"`
	SMTP          SMTPConfig     `toml:"smtp"`
	Cache         CacheConfig    `toml:"cache"`
}

type PostgresConfig struct {
	Host     string `toml:"host"`
	Port     int    `toml:"port"`
	User     string `toml:"user"`
	Password string `toml:"password"`
	DBName   string `toml:"dbname"`
	SSLMode  string `toml:"sslmode"`
}

type TokenConfig struct {
	Secret     string `toml:"secret"`
	AccessTTL  int    `toml:"access_ttl_sec"`
	RefreshTTL int    `toml:"refresh_ttl_sec"`
}

func LoadConfig(configPath string) (*Config, error) {
	var config Config

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, err
	}

	if _, err := toml.DecodeFile(configPath, &config); err != nil {
		return nil, err
	}

	s := &config.Auth.Log
	s.Path = config.Log.Path + "/" + s.Path
	if s.Level == "" {
		s.Level = config.Log.Level
	}

	return &config, nil
}

package main

import (
	"auth/internal/adapter/database"
	"auth/internal/adapter/logger"
	"fmt"
	"time"
	_ "time/tzdata"

	sqlxRepo "auth/internal/adapter/repository/sqlx"
	"auth/internal/adapter/service/otp2fa"
	"auth/internal/adapter/service/tokengen/jwt"
	user "auth/internal/adapter/service/user/http"

	v1api "auth/internal/api/v1"
	v2api "auth/internal/api/v2"
	"auth/internal/config"
	v1handler "auth/internal/handler/v1"
	v2handler "auth/internal/handler/v2"
	"auth/internal/middleware"
	usecase "auth/internal/usecase/v1"
	"log"
	"net/http"

	"auth/internal/adapter/cache"

	"github.com/gorilla/mux"
)

func init() {
	loc, err := time.LoadLocation("Europe/Moscow")
	if err != nil {
		log.Fatalf("Couldn't set timezone: %v", err)
	}
	time.Local = loc
}

func main() {
	cfg, err := config.LoadConfig("config.toml")
	if err != nil {
		log.Println("Error reading config (config.toml)")
	}

	logger := logger.NewZapLogger(cfg.Auth.Log)

	db, err := database.NewPostgresDB(cfg.Auth.Postgres)
	if err != nil {
		log.Println("Couldn't connect to database, exiting")
		return
	}

	repo := sqlxRepo.NewSQLXTokenRepository(db)

	baseURL := fmt.Sprintf("http://%s:%d/%s", cfg.User.ContainerName, cfg.User.LocalPort, cfg.User.BaseURL)

	userService := user.NewHTTPUserService(baseURL, 2*time.Second)
	tokenService := jwt.NewJWTService(
		cfg.Auth.Token.Secret,
		time.Duration(cfg.Auth.Token.AccessTTL)*time.Second,
		time.Duration(cfg.Auth.Token.RefreshTTL)*time.Second,
	)

	otp2faRepo := sqlxRepo.NewSQLXOTP2FARepository(db)
	otp2faService := otp2fa.NewOTP2FAService(otp2faRepo, logger)

	usecaseConfig := &config.UsecaseConfig{
		SMTP:  cfg.Auth.SMTP,
		Cache: cfg.Auth.Cache,
	}

	cache := cache.NewInMemoryCache()

	uc := usecase.NewAuthUseCase(repo, userService, tokenService, otp2faService, logger, *usecaseConfig, cache)

	v1h := v1handler.NewAuthHandler(uc)
	v2h := v2handler.NewAuthHandler(uc)
	router := mux.NewRouter()
	loggingMiddleware := middleware.NewLoggingMiddleware(logger)
	router.Use(loggingMiddleware.Middleware)
	v1api.InitializeV1Routes(router, v1h)
	v2api.InitializeV2Routes(router, v1h, v2h)

	localPort := fmt.Sprintf("%d", cfg.Auth.LocalPort)
	exposedPort := fmt.Sprintf("%d", cfg.Auth.ExposedPort)

	log.Printf("Starting server on :%s\n", exposedPort)
	http.ListenAndServe(":"+localPort, router)
}

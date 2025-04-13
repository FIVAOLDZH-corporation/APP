//go:build integration

package integration_test

import (
	lg "auth/internal/adapter/logger"
	"auth/internal/adapter/service/otp2fa"
	"auth/internal/adapter/service/tokengen/jwt"
	user "auth/internal/adapter/service/user/http"
	"auth/tests/integration/utils"
	"context"
	"log"
	"testing"
	"time"

	sqlxRepo "auth/internal/adapter/repository/sqlx"
	v1 "auth/internal/usecase/v1"

	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
)

func TestRegister(t *testing.T) {
	runner.Run(t, "TestRegister", func(pt provider.T) {
		tests := []struct {
			name     string
			username string
			email    string
			password string
			wantErr  bool
			err      error
		}{
			{
				name:     "positive",
				username: "PositiveUsername",
				email:    "positive@email.com",
				password: "P0s1t1v3P@ssw0rD",
				wantErr:  false,
			},
			{
				name:     "negative",
				username: "NegativeUsername",
				email:    "negative@email.com",
				password: "np",
				wantErr:  true,
				err:      v1.ErrCreateUser,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					db, err := utils.NewTestDB()
					if err != nil {
						log.Fatal(err)
					}
					tokenRepo := sqlxRepo.NewSQLXTokenRepository(db)

					// baseURL := "http://localhost:8001/api/v1"
					baseURL := "http://docker:8001/api/v1"

					userSvc := user.NewHTTPUserService(baseURL, 2*time.Second)
					tokenSvc := jwt.NewJWTService(
						"secret",
						time.Duration(900)*time.Second,
						time.Duration(604800)*time.Second,
					)

					logger := lg.NewEmptyLogger()

					otp2faRepo := sqlxRepo.NewSQLXOTP2FARepository(db)
					otp2faSvc := otp2fa.NewOTP2FAService(otp2faRepo, logger)

					uc := v1.NewAuthUseCase(tokenRepo, userSvc, tokenSvc, otp2faSvc, logger)

					pt.WithNewStep("Call Register", func(sCtx provider.StepCtx) {
						_, err := uc.Register(context.Background(), tt.username, tt.email, tt.password)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}
					})
				})
			})
		}
	})
}

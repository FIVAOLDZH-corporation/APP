//go:build e2e

package e2e_test

import (
	lg "aggregator/internal/adapter/logger"
	v1 "aggregator/internal/usecase/v1"

	auth "aggregator/internal/service/auth"
	todo "aggregator/internal/service/todo"
	user "aggregator/internal/service/user"

	httpAuth "aggregator/internal/adapter/service/auth/http"
	httpTodo "aggregator/internal/adapter/service/todo/http"
	httpUser "aggregator/internal/adapter/service/user/http"

	"context"
	"testing"
	"time"

	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
)

func TestRegisterE2E(t *testing.T) {
	runner.Run(t, "TestRegisterE2E", func(pt provider.T) {
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
				username: "AggPositiveUsername",
				email:    "aggpositive@email.com",
				password: "AggP0s1t1v3P@ssw0rD",
				wantErr:  false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					logger := lg.NewEmptyLogger()

					var userSvc user.UserService
					{
						// baseURL := "http://localhost:8001/api/v1"
						baseURL := "http://docker:8001/api/v1"
						userSvc = httpUser.NewUserService(baseURL, 2*time.Second, logger)
					}

					var authSvc auth.AuthService
					{
						// baseURL := "http://localhost:8002/api/v2"
						baseURL := "http://docker:8002/api/v2"
						authSvc = httpAuth.NewAuthService(baseURL, 2*time.Second, logger)
					}

					var todoSvc todo.TodoService
					{
						// baseURL := "http://localhost:8003/api/v1"
						baseURL := "http://docker:8003/api/v1"
						todoSvc = httpTodo.NewTodoService(baseURL, 2*time.Second, logger)
					}

					uc := v1.NewAggregatorUseCase(userSvc, authSvc, todoSvc, logger)

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

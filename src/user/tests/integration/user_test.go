//go:build integration

package integration_test

import (
	"context"
	"log"
	"testing"
	lg "user/internal/adapter/logger"
	repo "user/internal/adapter/repository/sqlx"
	"user/internal/entity"
	"user/internal/testdata"
	v1 "user/internal/usecase/v1"
	"user/tests/integration/utils"

	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"

	_ "github.com/lib/pq"
)

func TestCreateUser(t *testing.T) {
	runner.Run(t, "Test CreateUser", func(pt provider.T) {
		objectMother := &testdata.UserObjectMother{}

		tests := []struct {
			name    string
			user    entity.User
			wantErr bool
			err     error
		}{
			{
				name:    "positive",
				user:    objectMother.ValidUser(),
				wantErr: false,
			},
			{
				name:    "negative",
				user:    objectMother.InvalidEmailUser(),
				wantErr: true,
				err:     v1.ErrInvalidEmailFormat,
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

					repo := repo.NewSQLXUserRepository(db)
					logger := lg.NewEmptyLogger()
					userUC := v1.NewUserUseCase(repo, logger)

					pt.WithNewStep("Call CreateUser", func(sCtx provider.StepCtx) {
						err := userUC.CreateUser(context.Background(), tt.user)

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

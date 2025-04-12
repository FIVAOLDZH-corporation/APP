//go:build integration

package integration_test

import (
	"context"
	"log"
	"testing"
	lg "todo/internal/adapter/logger"
	"todo/internal/entity"

	"todo/tests/integration/utils"

	sqlxRepo "todo/internal/adapter/repository/sqlx"

	"todo/internal/testdata"
	v1 "todo/internal/usecase/v1"

	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
)

func TestCreateBoard(t *testing.T) {
	runner.Run(t, "TestCreateBoard", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name    string
			board   entity.Board
			wantErr bool
			err     error
		}{
			{
				name: "positive",
				board: entity.Board{
					ID:     mom.GetUUID(0),
					UserID: mom.GetUUID(1),
					Title:  "PositiveBoard",
				},
				wantErr: false,
			},
			// {
			// 	name: "negative",
			// 	board: entity.Board{
			// 		ID:     mom.GetUUID(0),
			// 		UserID: mom.GetUUID(1),
			// 		Title:  "NegativeBoard",
			// 	},
			// 	wantErr: true,
			// 	err:     v1.ErrCreateBoard,
			// },
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					db, err := utils.NewTestDB()
					if err != nil {
						log.Fatal(err)
					}

					boardRepo := sqlxRepo.NewSQLXBoardRepository(db)
					columnRepo := sqlxRepo.NewSQLXColumnRepository(db)
					cardRepo := sqlxRepo.NewSQLXCardRepository(db)
					logger := lg.NewEmptyLogger()

					uc := v1.NewTodoUseCase(boardRepo, columnRepo, cardRepo, logger)

					pt.WithNewStep("Call CreateBoard", func(sCtx provider.StepCtx) {
						err := uc.CreateBoard(context.Background(), &tt.board)

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

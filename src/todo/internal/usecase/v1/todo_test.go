//go:build unit

package v1_test

import (
	"context"
	"errors"
	"testing"
	"time"
	log "todo/internal/adapter/logger"
	"todo/internal/entity"
	"todo/internal/usecase/v1"
	"todo/mocks"

	"github.com/google/uuid"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
	"todo/internal/testdata"
)

func TestCreateBoard(t *testing.T) {
	runner.Run(t, "TestCreateBoard", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			board     entity.Board
			mockSetup func(mockBoardRepo *mocks.BoardRepository, board *entity.Board)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				board: entity.Board{
					ID:     mom.GetUUID(0),
					UserID: mom.GetUUID(1),
					Title:  "PositiveBoard",
				},
				mockSetup: func(mockBoardRepo *mocks.BoardRepository, board *entity.Board) {
					mockBoardRepo.On("CreateBoard", context.Background(), board).Return(nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				board: entity.Board{
					ID:     mom.GetUUID(0),
					UserID: mom.GetUUID(1),
					Title:  "NegativeBoard",
				},
				mockSetup: func(mockBoardRepo *mocks.BoardRepository, board *entity.Board) {
					mockBoardRepo.On("CreateBoard", context.Background(), board).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrCreateBoard,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockBoardRepo := new(mocks.BoardRepository)
					mockColumnRepo := new(mocks.ColumnRepository)
					mockCardRepo := new(mocks.CardRepository)
					logger := log.NewEmptyLogger()

					uc := v1.NewTodoUseCase(mockBoardRepo, mockColumnRepo, mockCardRepo, logger)

					tt.mockSetup(mockBoardRepo, &tt.board)

					pt.WithNewStep("Call CreateBoard", func(sCtx provider.StepCtx) {
						err := uc.CreateBoard(context.Background(), &tt.board)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockCardRepo.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestCreateColumn(t *testing.T) {
	runner.Run(t, "TestCreateColumn", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			column    entity.Column
			mockSetup func(mockColumnRepo *mocks.ColumnRepository, column *entity.Column)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				column: entity.Column{
					ID:      mom.GetUUID(0),
					UserID:  mom.GetUUID(1),
					BoardID: mom.GetUUID(2),
					Title:   "PositiveColumn",
				},
				mockSetup: func(mockColumnRepo *mocks.ColumnRepository, column *entity.Column) {
					mockColumnRepo.On("CreateColumn", context.Background(), column).Return(nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				column: entity.Column{
					ID:      mom.GetUUID(0),
					UserID:  mom.GetUUID(1),
					BoardID: mom.GetUUID(2),
					Title:   "NegativeColumn",
				},
				mockSetup: func(mockColumnRepo *mocks.ColumnRepository, column *entity.Column) {
					mockColumnRepo.On("CreateColumn", context.Background(), column).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrCreateColumn,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockBoardRepo := new(mocks.BoardRepository)
					mockColumnRepo := new(mocks.ColumnRepository)
					mockCardRepo := new(mocks.CardRepository)
					logger := log.NewEmptyLogger()

					uc := v1.NewTodoUseCase(mockBoardRepo, mockColumnRepo, mockCardRepo, logger)

					tt.mockSetup(mockColumnRepo, &tt.column)

					pt.WithNewStep("Call CreateColumn", func(sCtx provider.StepCtx) {
						err := uc.CreateColumn(context.Background(), &tt.column)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockCardRepo.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestCreateCard(t *testing.T) {
	runner.Run(t, "TestCreateCard", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			card      entity.Card
			mockSetup func(mockCardRepo *mocks.CardRepository, card *entity.Card)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				card: entity.Card{
					ID:       mom.GetUUID(0),
					UserID:   mom.GetUUID(1),
					ColumnID: mom.GetUUID(2),
					Title:    "PositiveCard",
				},
				mockSetup: func(mockCardRepo *mocks.CardRepository, card *entity.Card) {
					mockCardRepo.On("CreateCard", context.Background(), card).Return(nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				card: entity.Card{
					ID:       mom.GetUUID(0),
					UserID:   mom.GetUUID(1),
					ColumnID: mom.GetUUID(2),
					Title:    "NegativeCard",
				},
				mockSetup: func(mockCardRepo *mocks.CardRepository, card *entity.Card) {
					mockCardRepo.On("CreateCard", context.Background(), card).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrCreateCard,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockBoardRepo := new(mocks.BoardRepository)
					mockColumnRepo := new(mocks.ColumnRepository)
					mockCardRepo := new(mocks.CardRepository)
					logger := log.NewEmptyLogger()

					uc := v1.NewTodoUseCase(mockBoardRepo, mockColumnRepo, mockCardRepo, logger)

					tt.mockSetup(mockCardRepo, &tt.card)

					pt.WithNewStep("Call CreateCard", func(sCtx provider.StepCtx) {
						err := uc.CreateCard(context.Background(), &tt.card)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockCardRepo.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestGetBoardByID(t *testing.T) {
	runner.Run(t, "TestGetBoardByID", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			id        uuid.UUID
			mockSetup func(mockBoardRepo *mocks.BoardRepository, id uuid.UUID)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				id:   mom.GetUUID(0),
				mockSetup: func(mockBoardRepo *mocks.BoardRepository, id uuid.UUID) {
					boardEntity := entity.Board{
						ID:     id,
						UserID: mom.GetUUID(1),
						Title:  "Board",
					}

					mockBoardRepo.On("GetBoardByID", context.Background(), id).Return(&boardEntity, nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				id:   mom.GetUUID(0),
				mockSetup: func(mockBoardRepo *mocks.BoardRepository, id uuid.UUID) {
					mockBoardRepo.On("GetBoardByID", context.Background(), id).Return(nil, errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrGetBoardByID,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockBoardRepo := new(mocks.BoardRepository)
					mockColumnRepo := new(mocks.ColumnRepository)
					mockCardRepo := new(mocks.CardRepository)
					logger := log.NewEmptyLogger()

					uc := v1.NewTodoUseCase(mockBoardRepo, mockColumnRepo, mockCardRepo, logger)

					tt.mockSetup(mockBoardRepo, tt.id)

					pt.WithNewStep("Call GetBoardByID", func(sCtx provider.StepCtx) {
						_, err := uc.GetBoardByID(context.Background(), tt.id)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockBoardRepo.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestGetColumnByID(t *testing.T) {
	runner.Run(t, "TestGetColumnByID", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			id        uuid.UUID
			mockSetup func(mockColumnRepo *mocks.ColumnRepository, id uuid.UUID)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				id:   mom.GetUUID(0),
				mockSetup: func(mockColumnRepo *mocks.ColumnRepository, id uuid.UUID) {
					columnEntity := entity.Column{
						ID:      id,
						UserID:  mom.GetUUID(1),
						BoardID: mom.GetUUID(2),
						Title:   "Column",
					}

					mockColumnRepo.On("GetColumnByID", context.Background(), id).Return(&columnEntity, nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				id:   mom.GetUUID(0),
				mockSetup: func(mockColumnRepo *mocks.ColumnRepository, id uuid.UUID) {
					mockColumnRepo.On("GetColumnByID", context.Background(), id).Return(nil, errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrGetColumnByID,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockBoardRepo := new(mocks.BoardRepository)
					mockColumnRepo := new(mocks.ColumnRepository)
					mockCardRepo := new(mocks.CardRepository)
					logger := log.NewEmptyLogger()

					uc := v1.NewTodoUseCase(mockBoardRepo, mockColumnRepo, mockCardRepo, logger)

					tt.mockSetup(mockColumnRepo, tt.id)

					pt.WithNewStep("Call GetColumnByID", func(sCtx provider.StepCtx) {
						_, err := uc.GetColumnByID(context.Background(), tt.id)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockColumnRepo.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestGetCardByID(t *testing.T) {
	runner.Run(t, "TestGetCardByID", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			id        uuid.UUID
			mockSetup func(mockCardRepo *mocks.CardRepository, id uuid.UUID)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				id:   mom.GetUUID(0),
				mockSetup: func(mockCardRepo *mocks.CardRepository, id uuid.UUID) {
					cardEntity := entity.Card{
						ID:       id,
						UserID:   mom.GetUUID(1),
						ColumnID: mom.GetUUID(2),
						Title:    "Card",
					}

					mockCardRepo.On("GetCardByID", context.Background(), id).Return(&cardEntity, nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				id:   mom.GetUUID(0),
				mockSetup: func(mockCardRepo *mocks.CardRepository, id uuid.UUID) {
					mockCardRepo.On("GetCardByID", context.Background(), id).Return(nil, errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrGetCardByID,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockBoardRepo := new(mocks.BoardRepository)
					mockColumnRepo := new(mocks.ColumnRepository)
					mockCardRepo := new(mocks.CardRepository)
					logger := log.NewEmptyLogger()

					uc := v1.NewTodoUseCase(mockBoardRepo, mockColumnRepo, mockCardRepo, logger)

					tt.mockSetup(mockCardRepo, tt.id)

					pt.WithNewStep("Call GetCardByID", func(sCtx provider.StepCtx) {
						_, err := uc.GetCardByID(context.Background(), tt.id)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockCardRepo.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestGetBoardsByUser(t *testing.T) {
	runner.Run(t, "TestGetBoardsByUser", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			userID    uuid.UUID
			limit     int
			offset    int
			mockSetup func(mockBoardRepo *mocks.BoardRepository, userID uuid.UUID, limit, offset int)
			wantErr   bool
			err       error
		}{
			{
				name:   "positive",
				userID: mom.GetUUID(0),
				limit:  3,
				offset: 0,
				mockSetup: func(mockBoardRepo *mocks.BoardRepository, userID uuid.UUID, limit, offset int) {
					boardEntities := make([]entity.Board, 3)

					boardEntities[0] = entity.Board{
						ID:     mom.GetUUID(1),
						UserID: userID,
						Title:  "BoardZero",
					}
					boardEntities[1] = entity.Board{
						ID:     mom.GetUUID(2),
						UserID: userID,
						Title:  "BoardOne",
					}
					boardEntities[2] = entity.Board{
						ID:     mom.GetUUID(3),
						UserID: userID,
						Title:  "BoardTwo",
					}

					mockBoardRepo.On("GetBoardsByUser", context.Background(), userID, limit, offset).Return(boardEntities, nil)
				},
				wantErr: false,
			},
			{
				name:   "negative",
				userID: mom.GetUUID(0),
				limit:  3,
				offset: 0,
				mockSetup: func(mockBoardRepo *mocks.BoardRepository, userID uuid.UUID, limit, offset int) {
					mockBoardRepo.On("GetBoardsByUser", context.Background(), userID, limit, offset).Return(nil, errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrGetBoardsByUser,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockBoardRepo := new(mocks.BoardRepository)
					mockColumnRepo := new(mocks.ColumnRepository)
					mockCardRepo := new(mocks.CardRepository)
					logger := log.NewEmptyLogger()

					uc := v1.NewTodoUseCase(mockBoardRepo, mockColumnRepo, mockCardRepo, logger)

					tt.mockSetup(mockBoardRepo, tt.userID, tt.limit, tt.offset)

					pt.WithNewStep("Call GetBoardsByUser", func(sCtx provider.StepCtx) {
						_, err := uc.GetBoardsByUser(context.Background(), tt.userID, tt.limit, tt.offset)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockBoardRepo.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestGetColumnsByBoard(t *testing.T) {
	runner.Run(t, "TestGetColumnsByBoard", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			boardID   uuid.UUID
			limit     int
			offset    int
			mockSetup func(mockColumnRepo *mocks.ColumnRepository, boardID uuid.UUID, limit, offset int)
			wantErr   bool
			err       error
		}{
			{
				name:    "positive",
				boardID: mom.GetUUID(0),
				limit:   3,
				offset:  0,
				mockSetup: func(mockColumnRepo *mocks.ColumnRepository, boardID uuid.UUID, limit, offset int) {
					columnEntities := make([]entity.Column, 3)

					columnEntities[0] = entity.Column{
						ID:      mom.GetUUID(1),
						UserID:  mom.GetUUID(2),
						BoardID: boardID,
						Title:   "ColumnZero",
					}
					columnEntities[1] = entity.Column{
						ID:      mom.GetUUID(3),
						UserID:  mom.GetUUID(4),
						BoardID: boardID,
						Title:   "ColumnOne",
					}
					columnEntities[2] = entity.Column{
						ID:      mom.GetUUID(5),
						UserID:  mom.GetUUID(6),
						BoardID: boardID,
						Title:   "ColumnTwo",
					}

					mockColumnRepo.On("GetColumnsByBoard", context.Background(), boardID, limit, offset).Return(columnEntities, nil)
				},
				wantErr: false,
			},
			{
				name:    "negative",
				boardID: mom.GetUUID(0),
				limit:   3,
				offset:  0,
				mockSetup: func(mockColumnRepo *mocks.ColumnRepository, boardID uuid.UUID, limit, offset int) {
					mockColumnRepo.On("GetColumnsByBoard", context.Background(), boardID, limit, offset).Return(nil, errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrGetColumnsByBoard,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockBoardRepo := new(mocks.BoardRepository)
					mockColumnRepo := new(mocks.ColumnRepository)
					mockCardRepo := new(mocks.CardRepository)
					logger := log.NewEmptyLogger()

					uc := v1.NewTodoUseCase(mockBoardRepo, mockColumnRepo, mockCardRepo, logger)

					tt.mockSetup(mockColumnRepo, tt.boardID, tt.limit, tt.offset)

					pt.WithNewStep("Call GetColumnsByBoard", func(sCtx provider.StepCtx) {
						_, err := uc.GetColumnsByBoard(context.Background(), tt.boardID, tt.limit, tt.offset)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockColumnRepo.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestGetCardsByColumn(t *testing.T) {
	runner.Run(t, "TestGetCardsByColumn", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			columnID  uuid.UUID
			limit     int
			offset    int
			mockSetup func(mockCardRepo *mocks.CardRepository, columnID uuid.UUID, limit, offset int)
			wantErr   bool
			err       error
		}{
			{
				name:     "positive",
				columnID: mom.GetUUID(0),
				limit:    3,
				offset:   0,
				mockSetup: func(mockCardRepo *mocks.CardRepository, columnID uuid.UUID, limit, offset int) {
					cardEntities := make([]entity.Card, 3)

					cardEntities[0] = entity.Card{
						ID:       mom.GetUUID(1),
						UserID:   mom.GetUUID(2),
						ColumnID: columnID,
						Title:    "CardZero",
					}
					cardEntities[1] = entity.Card{
						ID:       mom.GetUUID(3),
						UserID:   mom.GetUUID(4),
						ColumnID: columnID,
						Title:    "CardOne",
					}
					cardEntities[2] = entity.Card{
						ID:       mom.GetUUID(5),
						UserID:   mom.GetUUID(6),
						ColumnID: columnID,
						Title:    "CardTwo",
					}

					mockCardRepo.On("GetCardsByColumn", context.Background(), columnID, limit, offset).Return(cardEntities, nil)
				},
				wantErr: false,
			},
			{
				name:     "negative",
				columnID: mom.GetUUID(0),
				limit:    3,
				offset:   0,
				mockSetup: func(mockCardRepo *mocks.CardRepository, columnID uuid.UUID, limit, offset int) {
					mockCardRepo.On("GetCardsByColumn", context.Background(), columnID, limit, offset).Return(nil, errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrGetCardsByColumn,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockBoardRepo := new(mocks.BoardRepository)
					mockColumnRepo := new(mocks.ColumnRepository)
					mockCardRepo := new(mocks.CardRepository)
					logger := log.NewEmptyLogger()

					uc := v1.NewTodoUseCase(mockBoardRepo, mockColumnRepo, mockCardRepo, logger)

					tt.mockSetup(mockCardRepo, tt.columnID, tt.limit, tt.offset)

					pt.WithNewStep("Call GetCardsByColumn", func(sCtx provider.StepCtx) {
						_, err := uc.GetCardsByColumn(context.Background(), tt.columnID, tt.limit, tt.offset)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockCardRepo.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestGetNewCards(t *testing.T) {
	runner.Run(t, "TestGetNewCards", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		fromTime := time.Date(2023, 9, 1, 0, 0, 0, 0, time.UTC)
		toTime := time.Date(2023, 9, 30, 23, 59, 59, 0, time.UTC)

		tests := []struct {
			name      string
			from      time.Time
			to        time.Time
			mockSetup func(mockCardRepo *mocks.CardRepository, from, to time.Time)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				from: fromTime,
				to:   toTime,
				mockSetup: func(mockCardRepo *mocks.CardRepository, from, to time.Time) {
					cardEntities := make([]entity.Card, 3)

					cardEntities[0] = entity.Card{
						ID:       mom.GetUUID(0),
						UserID:   mom.GetUUID(1),
						ColumnID: mom.GetUUID(2),
						Title:    "CardZero",
					}
					cardEntities[1] = entity.Card{
						ID:       mom.GetUUID(3),
						UserID:   mom.GetUUID(4),
						ColumnID: mom.GetUUID(5),
						Title:    "CardOne",
					}
					cardEntities[2] = entity.Card{
						ID:       mom.GetUUID(6),
						UserID:   mom.GetUUID(7),
						ColumnID: mom.GetUUID(8),
						Title:    "CardTwo",
					}

					mockCardRepo.On("GetNewCards", context.Background(), from, to).Return(cardEntities, nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				from: fromTime,
				to:   toTime,
				mockSetup: func(mockCardRepo *mocks.CardRepository, from, to time.Time) {
					mockCardRepo.On("GetNewCards", context.Background(), from, to).Return(nil, errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrGetNewCards,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockBoardRepo := new(mocks.BoardRepository)
					mockColumnRepo := new(mocks.ColumnRepository)
					mockCardRepo := new(mocks.CardRepository)
					logger := log.NewEmptyLogger()

					uc := v1.NewTodoUseCase(mockBoardRepo, mockColumnRepo, mockCardRepo, logger)

					tt.mockSetup(mockCardRepo, tt.from, tt.to)

					pt.WithNewStep("Call GetNewCards", func(sCtx provider.StepCtx) {
						_, err := uc.GetNewCards(context.Background(), tt.from, tt.to)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockCardRepo.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestUpdateBoard(t *testing.T) {
	runner.Run(t, "TestUpdateBoard", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			board     entity.Board
			mockSetup func(mockBoardRepo *mocks.BoardRepository, board *entity.Board)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				board: entity.Board{
					ID:     mom.GetUUID(0),
					UserID: mom.GetUUID(1),
					Title:  "PositiveBoard",
				},
				mockSetup: func(mockBoardRepo *mocks.BoardRepository, board *entity.Board) {
					mockBoardRepo.On("UpdateBoard", context.Background(), board).Return(nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				board: entity.Board{
					ID:     mom.GetUUID(0),
					UserID: mom.GetUUID(1),
					Title:  "NegativeBoard",
				},
				mockSetup: func(mockBoardRepo *mocks.BoardRepository, board *entity.Board) {
					mockBoardRepo.On("UpdateBoard", context.Background(), board).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrUpdateBoard,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockBoardRepo := new(mocks.BoardRepository)
					mockColumnRepo := new(mocks.ColumnRepository)
					mockCardRepo := new(mocks.CardRepository)
					logger := log.NewEmptyLogger()

					uc := v1.NewTodoUseCase(mockBoardRepo, mockColumnRepo, mockCardRepo, logger)

					tt.mockSetup(mockBoardRepo, &tt.board)

					pt.WithNewStep("Call UpdateBoard", func(sCtx provider.StepCtx) {
						err := uc.UpdateBoard(context.Background(), &tt.board)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockCardRepo.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestUpdateColumn(t *testing.T) {
	runner.Run(t, "TestUpdateColumn", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			column    entity.Column
			mockSetup func(mockColumnRepo *mocks.ColumnRepository, column *entity.Column)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				column: entity.Column{
					ID:      mom.GetUUID(0),
					UserID:  mom.GetUUID(1),
					BoardID: mom.GetUUID(2),
					Title:   "PositiveColumn",
				},
				mockSetup: func(mockColumnRepo *mocks.ColumnRepository, column *entity.Column) {
					mockColumnRepo.On("UpdateColumn", context.Background(), column).Return(nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				column: entity.Column{
					ID:      mom.GetUUID(0),
					UserID:  mom.GetUUID(1),
					BoardID: mom.GetUUID(2),
					Title:   "NegativeColumn",
				},
				mockSetup: func(mockColumnRepo *mocks.ColumnRepository, column *entity.Column) {
					mockColumnRepo.On("UpdateColumn", context.Background(), column).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrUpdateColumn,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockBoardRepo := new(mocks.BoardRepository)
					mockColumnRepo := new(mocks.ColumnRepository)
					mockCardRepo := new(mocks.CardRepository)
					logger := log.NewEmptyLogger()

					uc := v1.NewTodoUseCase(mockBoardRepo, mockColumnRepo, mockCardRepo, logger)

					tt.mockSetup(mockColumnRepo, &tt.column)

					pt.WithNewStep("Call UpdateColumn", func(sCtx provider.StepCtx) {
						err := uc.UpdateColumn(context.Background(), &tt.column)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockCardRepo.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestUpdateCard(t *testing.T) {
	runner.Run(t, "TestUpdateCard", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			card      entity.Card
			mockSetup func(mockCardRepo *mocks.CardRepository, card *entity.Card)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				card: entity.Card{
					ID:       mom.GetUUID(0),
					UserID:   mom.GetUUID(1),
					ColumnID: uuid.Nil,
					Title:    "PositiveCard",
				},
				mockSetup: func(mockCardRepo *mocks.CardRepository, card *entity.Card) {
					mockCardRepo.On("UpdateCard", context.Background(), card).Return(nil)
				},
				wantErr: false,
			},
			{
				name: "positive move",
				card: entity.Card{
					ID:       mom.GetUUID(0),
					UserID:   mom.GetUUID(1),
					ColumnID: mom.GetUUID(2),
					Title:    "PositiveCard",
				},
				mockSetup: func(mockCardRepo *mocks.CardRepository, card *entity.Card) {
					mockCardRepo.On("MoveCard", context.Background(), card).Return(nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				card: entity.Card{
					ID:       mom.GetUUID(0),
					UserID:   mom.GetUUID(1),
					ColumnID: uuid.Nil,
					Title:    "NegativeCard",
				},
				mockSetup: func(mockCardRepo *mocks.CardRepository, card *entity.Card) {
					mockCardRepo.On("UpdateCard", context.Background(), card).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrUpdateCard,
			},
			{
				name: "negative move",
				card: entity.Card{
					ID:       mom.GetUUID(0),
					UserID:   mom.GetUUID(1),
					ColumnID: mom.GetUUID(2),
					Title:    "NegativeCard",
				},
				mockSetup: func(mockCardRepo *mocks.CardRepository, card *entity.Card) {
					mockCardRepo.On("MoveCard", context.Background(), card).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrUpdateCard,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockBoardRepo := new(mocks.BoardRepository)
					mockColumnRepo := new(mocks.ColumnRepository)
					mockCardRepo := new(mocks.CardRepository)
					logger := log.NewEmptyLogger()

					uc := v1.NewTodoUseCase(mockBoardRepo, mockColumnRepo, mockCardRepo, logger)

					tt.mockSetup(mockCardRepo, &tt.card)

					pt.WithNewStep("Call UpdateCard", func(sCtx provider.StepCtx) {
						err := uc.UpdateCard(context.Background(), &tt.card)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockCardRepo.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestDeleteBoard(t *testing.T) {
	runner.Run(t, "TestDeleteBoard", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			id        uuid.UUID
			mockSetup func(mockBoardRepo *mocks.BoardRepository, id uuid.UUID)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				id:   mom.GetUUID(0),
				mockSetup: func(mockBoardRepo *mocks.BoardRepository, id uuid.UUID) {
					mockBoardRepo.On("DeleteBoard", context.Background(), id).Return(nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				id:   mom.GetUUID(0),
				mockSetup: func(mockBoardRepo *mocks.BoardRepository, id uuid.UUID) {
					mockBoardRepo.On("DeleteBoard", context.Background(), id).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrDeleteBoard,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockBoardRepo := new(mocks.BoardRepository)
					mockColumnRepo := new(mocks.ColumnRepository)
					mockCardRepo := new(mocks.CardRepository)
					logger := log.NewEmptyLogger()

					uc := v1.NewTodoUseCase(mockBoardRepo, mockColumnRepo, mockCardRepo, logger)

					tt.mockSetup(mockBoardRepo, tt.id)

					pt.WithNewStep("Call DeleteBoard", func(sCtx provider.StepCtx) {
						err := uc.DeleteBoard(context.Background(), tt.id)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockCardRepo.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestDeleteColumn(t *testing.T) {
	runner.Run(t, "TestDeleteColumn", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			id        uuid.UUID
			mockSetup func(mockColumnRepo *mocks.ColumnRepository, id uuid.UUID)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				id:   mom.GetUUID(0),
				mockSetup: func(mockColumnRepo *mocks.ColumnRepository, id uuid.UUID) {
					mockColumnRepo.On("DeleteColumn", context.Background(), id).Return(nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				id:   mom.GetUUID(0),
				mockSetup: func(mockColumnRepo *mocks.ColumnRepository, id uuid.UUID) {
					mockColumnRepo.On("DeleteColumn", context.Background(), id).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrDeleteColumn,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockBoardRepo := new(mocks.BoardRepository)
					mockColumnRepo := new(mocks.ColumnRepository)
					mockCardRepo := new(mocks.CardRepository)
					logger := log.NewEmptyLogger()

					uc := v1.NewTodoUseCase(mockBoardRepo, mockColumnRepo, mockCardRepo, logger)

					tt.mockSetup(mockColumnRepo, tt.id)

					pt.WithNewStep("Call DeleteColumn", func(sCtx provider.StepCtx) {
						err := uc.DeleteColumn(context.Background(), tt.id)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockCardRepo.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestDeleteCard(t *testing.T) {
	runner.Run(t, "TestDeleteCard", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			id        uuid.UUID
			mockSetup func(mockCardRepo *mocks.CardRepository, id uuid.UUID)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				id:   mom.GetUUID(0),
				mockSetup: func(mockCardRepo *mocks.CardRepository, id uuid.UUID) {
					mockCardRepo.On("DeleteCard", context.Background(), id).Return(nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				id:   mom.GetUUID(0),
				mockSetup: func(mockCardRepo *mocks.CardRepository, id uuid.UUID) {
					mockCardRepo.On("DeleteCard", context.Background(), id).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrDeleteCard,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockBoardRepo := new(mocks.BoardRepository)
					mockColumnRepo := new(mocks.ColumnRepository)
					mockCardRepo := new(mocks.CardRepository)
					logger := log.NewEmptyLogger()

					uc := v1.NewTodoUseCase(mockBoardRepo, mockColumnRepo, mockCardRepo, logger)

					tt.mockSetup(mockCardRepo, tt.id)

					pt.WithNewStep("Call DeleteCard", func(sCtx provider.StepCtx) {
						err := uc.DeleteCard(context.Background(), tt.id)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockCardRepo.AssertExpectations(t)
					})
				})
			})
		}
	})
}

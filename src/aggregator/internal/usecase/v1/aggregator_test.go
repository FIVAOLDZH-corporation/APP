//go:build unit

package v1_test

import (
	log "aggregator/internal/adapter/logger"
	"aggregator/internal/dto"
	"aggregator/internal/testdata"
	"aggregator/mocks"
	"context"
	"errors"
	"testing"
	"time"

	v1 "aggregator/internal/usecase/v1"

	"github.com/google/uuid"
	"github.com/ozontech/allure-go/pkg/framework/provider"
	"github.com/ozontech/allure-go/pkg/framework/runner"
)

func TestGetStats(t *testing.T) {
	runner.Run(t, "TestGetStats", func(pt provider.T) {
		fromTime := time.Date(2023, 9, 1, 0, 0, 0, 0, time.UTC)
		toTime := time.Date(2023, 9, 30, 23, 59, 59, 0, time.UTC)

		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			from      time.Time
			to        time.Time
			mockSetup func(mockUserSvc *mocks.UserService, mockTodoSvc *mocks.TodoService, from, to time.Time)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				from: fromTime,
				to:   toTime,
				mockSetup: func(mockUserSvc *mocks.UserService, mockTodoSvc *mocks.TodoService, from, to time.Time) {
					userDTOs := make([]dto.User, 3)

					userDTOs[0] = dto.User{
						ID:       mom.GetUUID(0),
						Email:    "user@zero.com",
						Username: "UserZero",
					}
					userDTOs[1] = dto.User{
						ID:       mom.GetUUID(1),
						Email:    "user@one.com",
						Username: "UserOne",
					}
					userDTOs[2] = dto.User{
						ID:       mom.GetUUID(2),
						Email:    "user@two.com",
						Username: "UserTwo",
					}

					mockUserSvc.On("GetNewUsers", context.Background(), from, to).Return(userDTOs, nil)

					cardDTOs := make([]dto.Card, 3)

					cardDTOs[0] = dto.Card{
						ID:       mom.GetUUID(4),
						UserID:   mom.GetUUID(3),
						ColumnID: mom.GetUUID(5),
						Title:    "TitleZero",
					}
					cardDTOs[1] = dto.Card{
						ID:       mom.GetUUID(6),
						UserID:   userDTOs[1].ID,
						ColumnID: mom.GetUUID(7),
						Title:    "TitleOne",
					}
					cardDTOs[2] = dto.Card{
						ID:       mom.GetUUID(8),
						UserID:   userDTOs[2].ID,
						ColumnID: mom.GetUUID(9),
						Title:    "TitleTwo",
					}

					mockTodoSvc.On("GetNewCards", context.Background(), from, to).Return(cardDTOs, nil)
				},
				wantErr: false,
			},
			{
				name:      "negative",
				from:      toTime,
				to:        fromTime,
				mockSetup: func(mockUserSvc *mocks.UserService, mockTodoSvc *mocks.TodoService, from, to time.Time) {},
				wantErr:   true,
				err:       v1.ErrInvalidTimeRange,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockUserSvc := new(mocks.UserService)
					mockAuthSvc := new(mocks.AuthService)
					mockTodoSvc := new(mocks.TodoService)
					logger := log.NewEmptyLogger()

					uc := v1.NewAggregatorUseCase(mockUserSvc, mockAuthSvc, mockTodoSvc, logger)

					tt.mockSetup(mockUserSvc, mockTodoSvc, tt.from, tt.to)

					pt.WithNewStep("Call GetStats", func(sCtx provider.StepCtx) {
						_, err := uc.GetStats(context.Background(), tt.from, tt.to)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockUserSvc.AssertExpectations(t)
						mockTodoSvc.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestRegister(t *testing.T) {
	runner.Run(t, "TestRegister", func(pt provider.T) {
		tests := []struct {
			name      string
			username  string
			email     string
			password  string
			mockSetup func(mockAuthSvc *mocks.AuthService, username, email, password string)
			wantErr   bool
			err       error
		}{
			{
				name:     "positive",
				username: "PositiveUsername",
				email:    "positive@email.com",
				password: "P0s1t1v3P@ssw0rD",
				mockSetup: func(mockAuthSvc *mocks.AuthService, username, email, password string) {
					tokens := dto.Tokens{
						AccessToken:  "AccessToken",
						RefreshToken: "RefreshToken",
					}

					mockAuthSvc.On("Register", context.Background(), username, email, password).Return(&tokens, nil)
				},
				wantErr: false,
			},
			{
				name:     "negative",
				username: "NegativeUsername",
				email:    "negative@email.com",
				password: "N3g@t1v3P@ssw0rD",
				mockSetup: func(mockAuthSvc *mocks.AuthService, username, email, password string) {
					mockAuthSvc.On("Register", context.Background(), username, email, password).Return(nil, errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrRegister,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockUserSvc := new(mocks.UserService)
					mockAuthSvc := new(mocks.AuthService)
					mockTodoSvc := new(mocks.TodoService)
					logger := log.NewEmptyLogger()

					uc := v1.NewAggregatorUseCase(mockUserSvc, mockAuthSvc, mockTodoSvc, logger)

					tt.mockSetup(mockAuthSvc, tt.username, tt.email, tt.password)

					pt.WithNewStep("Call Register", func(sCtx provider.StepCtx) {
						_, err := uc.Register(context.Background(), tt.username, tt.email, tt.password)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockAuthSvc.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestLogin(t *testing.T) {
	runner.Run(t, "TestLogin", func(pt provider.T) {
		tests := []struct {
			name      string
			email     string
			password  string
			mockSetup func(mockAuthSvc *mocks.AuthService, email, password string)
			wantErr   bool
			err       error
		}{
			{
				name:     "positive",
				email:    "positive@email.com",
				password: "P0s1t1v3P@ssw0rD",
				mockSetup: func(mockAuthSvc *mocks.AuthService, email, password string) {
					tokens := dto.Tokens{
						AccessToken:  "AccessToken",
						RefreshToken: "RefreshToken",
					}

					mockAuthSvc.On("Login", context.Background(), email, password).Return(&tokens, nil)
				},
				wantErr: false,
			},
			{
				name:     "negative",
				email:    "negative@email.com",
				password: "N3g@t1v3P@ssw0rD",
				mockSetup: func(mockAuthSvc *mocks.AuthService, email, password string) {
					mockAuthSvc.On("Login", context.Background(), email, password).Return(nil, errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrLogin,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockUserSvc := new(mocks.UserService)
					mockAuthSvc := new(mocks.AuthService)
					mockTodoSvc := new(mocks.TodoService)
					logger := log.NewEmptyLogger()

					uc := v1.NewAggregatorUseCase(mockUserSvc, mockAuthSvc, mockTodoSvc, logger)

					tt.mockSetup(mockAuthSvc, tt.email, tt.password)

					pt.WithNewStep("Call Login", func(sCtx provider.StepCtx) {
						_, err := uc.Login(context.Background(), tt.email, tt.password)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockAuthSvc.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestRefresh(t *testing.T) {
	runner.Run(t, "TestRefresh", func(pt provider.T) {
		tests := []struct {
			name         string
			refreshToken string
			mockSetup    func(mockAuthSvc *mocks.AuthService, refreshToken string)
			wantErr      bool
			err          error
		}{
			{
				name:         "positive",
				refreshToken: "PositiveToken",
				mockSetup: func(mockAuthSvc *mocks.AuthService, refreshToken string) {
					resp := dto.RefreshResponse{
						AccessToken: "AccessToken",
					}

					mockAuthSvc.On("Refresh", context.Background(), refreshToken).Return(&resp, nil)
				},
				wantErr: false,
			},
			{
				name:         "negative",
				refreshToken: "NegativeToken",
				mockSetup: func(mockAuthSvc *mocks.AuthService, refreshToken string) {
					mockAuthSvc.On("Refresh", context.Background(), refreshToken).Return(nil, errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrRefresh,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockUserSvc := new(mocks.UserService)
					mockAuthSvc := new(mocks.AuthService)
					mockTodoSvc := new(mocks.TodoService)
					logger := log.NewEmptyLogger()

					uc := v1.NewAggregatorUseCase(mockUserSvc, mockAuthSvc, mockTodoSvc, logger)

					tt.mockSetup(mockAuthSvc, tt.refreshToken)

					pt.WithNewStep("Call Refresh", func(sCtx provider.StepCtx) {
						_, err := uc.Refresh(context.Background(), tt.refreshToken)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockAuthSvc.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestValidate(t *testing.T) {
	runner.Run(t, "TestValidate", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			token     string
			mockSetup func(mockAuthSvc *mocks.AuthService, token string)
			wantErr   bool
			err       error
		}{
			{
				name:  "positive",
				token: "PositiveToken",
				mockSetup: func(mockAuthSvc *mocks.AuthService, token string) {
					resp := dto.ValidateTokenResponse{
						UserID: mom.GetUUID(0).String(),
						Role:   "User",
					}

					mockAuthSvc.On("ValidateToken", context.Background(), token).Return(&resp, nil)
				},
				wantErr: false,
			},
			{
				name:  "negative",
				token: "NegativeToken",
				mockSetup: func(mockAuthSvc *mocks.AuthService, token string) {
					mockAuthSvc.On("ValidateToken", context.Background(), token).Return(nil, errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrValidate,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockUserSvc := new(mocks.UserService)
					mockAuthSvc := new(mocks.AuthService)
					mockTodoSvc := new(mocks.TodoService)
					logger := log.NewEmptyLogger()

					uc := v1.NewAggregatorUseCase(mockUserSvc, mockAuthSvc, mockTodoSvc, logger)

					tt.mockSetup(mockAuthSvc, tt.token)

					pt.WithNewStep("Call Validate", func(sCtx provider.StepCtx) {
						_, err := uc.Validate(context.Background(), tt.token)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockAuthSvc.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestLogout(t *testing.T) {
	runner.Run(t, "TestLogout", func(pt provider.T) {
		tests := []struct {
			name         string
			refreshToken string
			mockSetup    func(mockAuthSvc *mocks.AuthService, refreshToken string)
			wantErr      bool
			err          error
		}{
			{
				name:         "positive",
				refreshToken: "PositiveToken",
				mockSetup: func(mockAuthSvc *mocks.AuthService, refreshToken string) {
					mockAuthSvc.On("Logout", context.Background(), refreshToken).Return(nil)
				},
				wantErr: false,
			},
			{
				name:         "negative",
				refreshToken: "NegativeToken",
				mockSetup: func(mockAuthSvc *mocks.AuthService, refreshToken string) {
					mockAuthSvc.On("Logout", context.Background(), refreshToken).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrLogout,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockUserSvc := new(mocks.UserService)
					mockAuthSvc := new(mocks.AuthService)
					mockTodoSvc := new(mocks.TodoService)
					logger := log.NewEmptyLogger()

					uc := v1.NewAggregatorUseCase(mockUserSvc, mockAuthSvc, mockTodoSvc, logger)

					tt.mockSetup(mockAuthSvc, tt.refreshToken)

					pt.WithNewStep("Call Logout", func(sCtx provider.StepCtx) {
						err := uc.Logout(context.Background(), tt.refreshToken)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockAuthSvc.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestGetBoards(t *testing.T) {
	runner.Run(t, "TestGetBoards", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			userID    string
			mockSetup func(mockTodoSvc *mocks.TodoService, userID string)
			wantErr   bool
			err       error
		}{
			{
				name:   "positive",
				userID: mom.GetUUID(0).String(),
				mockSetup: func(mockTodoSvc *mocks.TodoService, userID string) {
					boardDTOs := make([]dto.Board, 3)

					uid, _ := uuid.Parse(userID)

					boardDTOs[0] = dto.Board{
						ID:     mom.GetUUID(1),
						UserID: uid,
						Title:  "BoardZero",
					}
					boardDTOs[1] = dto.Board{
						ID:     mom.GetUUID(2),
						UserID: uid,
						Title:  "BoardOne",
					}
					boardDTOs[2] = dto.Board{
						ID:     mom.GetUUID(3),
						UserID: uid,
						Title:  "BoardTwo",
					}

					mockTodoSvc.On("GetBoards", context.Background(), userID).Return(boardDTOs, nil)
				},
				wantErr: false,
			},
			{
				name:   "negative",
				userID: mom.GetUUID(0).String(),
				mockSetup: func(mockTodoSvc *mocks.TodoService, userID string) {
					mockTodoSvc.On("GetBoards", context.Background(), userID).Return(nil, errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrGetBoards,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockUserSvc := new(mocks.UserService)
					mockAuthSvc := new(mocks.AuthService)
					mockTodoSvc := new(mocks.TodoService)
					logger := log.NewEmptyLogger()

					uc := v1.NewAggregatorUseCase(mockUserSvc, mockAuthSvc, mockTodoSvc, logger)

					tt.mockSetup(mockTodoSvc, tt.userID)

					pt.WithNewStep("Call GetBoards", func(sCtx provider.StepCtx) {
						_, err := uc.GetBoards(context.Background(), tt.userID)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockTodoSvc.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestGetColumns(t *testing.T) {
	runner.Run(t, "TestGetColumns", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			boardID   string
			mockSetup func(mockTodoSvc *mocks.TodoService, boardID string)
			wantErr   bool
			err       error
		}{
			{
				name:    "positive",
				boardID: mom.GetUUID(0).String(),
				mockSetup: func(mockTodoSvc *mocks.TodoService, boardID string) {
					columnDTOs := make([]dto.Column, 3)

					bid, _ := uuid.Parse(boardID)

					columnDTOs[0] = dto.Column{
						ID:      mom.GetUUID(1),
						UserID:  mom.GetUUID(2),
						BoardID: bid,
						Title:   "columnZero",
					}
					columnDTOs[1] = dto.Column{
						ID:      mom.GetUUID(3),
						UserID:  mom.GetUUID(4),
						BoardID: bid,
						Title:   "columnOne",
					}
					columnDTOs[2] = dto.Column{
						ID:      mom.GetUUID(5),
						UserID:  mom.GetUUID(6),
						BoardID: bid,
						Title:   "columnTwo",
					}

					mockTodoSvc.On("GetColumns", context.Background(), boardID).Return(columnDTOs, nil)
				},
				wantErr: false,
			},
			{
				name:    "negative",
				boardID: mom.GetUUID(0).String(),
				mockSetup: func(mockTodoSvc *mocks.TodoService, boardID string) {
					mockTodoSvc.On("GetColumns", context.Background(), boardID).Return(nil, errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrGetColumns,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockUserSvc := new(mocks.UserService)
					mockAuthSvc := new(mocks.AuthService)
					mockTodoSvc := new(mocks.TodoService)
					logger := log.NewEmptyLogger()

					uc := v1.NewAggregatorUseCase(mockUserSvc, mockAuthSvc, mockTodoSvc, logger)

					tt.mockSetup(mockTodoSvc, tt.boardID)

					pt.WithNewStep("Call GetColumns", func(sCtx provider.StepCtx) {
						_, err := uc.GetColumns(context.Background(), tt.boardID)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockTodoSvc.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestGetCards(t *testing.T) {
	runner.Run(t, "TestGetCards", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			columnID  string
			mockSetup func(mockTodoSvc *mocks.TodoService, columnID string)
			wantErr   bool
			err       error
		}{
			{
				name:     "positive",
				columnID: mom.GetUUID(0).String(),
				mockSetup: func(mockTodoSvc *mocks.TodoService, columnID string) {
					cardDTOs := make([]dto.Card, 3)

					cid, _ := uuid.Parse(columnID)

					cardDTOs[0] = dto.Card{
						ID:       mom.GetUUID(1),
						UserID:   mom.GetUUID(2),
						ColumnID: cid,
						Title:    "CardZero",
					}
					cardDTOs[1] = dto.Card{
						ID:       mom.GetUUID(3),
						UserID:   mom.GetUUID(4),
						ColumnID: cid,
						Title:    "CardOne",
					}
					cardDTOs[2] = dto.Card{
						ID:       mom.GetUUID(5),
						UserID:   mom.GetUUID(6),
						ColumnID: cid,
						Title:    "CardTwo",
					}

					mockTodoSvc.On("GetCards", context.Background(), columnID).Return(cardDTOs, nil)
				},
				wantErr: false,
			},
			{
				name:     "negative",
				columnID: mom.GetUUID(0).String(),
				mockSetup: func(mockTodoSvc *mocks.TodoService, columnID string) {
					mockTodoSvc.On("GetCards", context.Background(), columnID).Return(nil, errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrGetCards,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockUserSvc := new(mocks.UserService)
					mockAuthSvc := new(mocks.AuthService)
					mockTodoSvc := new(mocks.TodoService)
					logger := log.NewEmptyLogger()

					uc := v1.NewAggregatorUseCase(mockUserSvc, mockAuthSvc, mockTodoSvc, logger)

					tt.mockSetup(mockTodoSvc, tt.columnID)

					pt.WithNewStep("Call GetCards", func(sCtx provider.StepCtx) {
						_, err := uc.GetCards(context.Background(), tt.columnID)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockTodoSvc.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestGetCard(t *testing.T) {
	runner.Run(t, "TestGetCard", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			id        string
			mockSetup func(mockTodoSvc *mocks.TodoService, id string)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				id:   mom.GetUUID(0).String(),
				mockSetup: func(mockTodoSvc *mocks.TodoService, id string) {
					cid, _ := uuid.Parse(id)

					cardDTO := dto.Card{
						ID:       cid,
						UserID:   mom.GetUUID(1),
						ColumnID: mom.GetUUID(2),
						Title:    "Card",
					}

					mockTodoSvc.On("GetCard", context.Background(), id).Return(&cardDTO, nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				id:   mom.GetUUID(0).String(),
				mockSetup: func(mockTodoSvc *mocks.TodoService, id string) {
					mockTodoSvc.On("GetCard", context.Background(), id).Return(nil, errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrGetCard,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockUserSvc := new(mocks.UserService)
					mockAuthSvc := new(mocks.AuthService)
					mockTodoSvc := new(mocks.TodoService)
					logger := log.NewEmptyLogger()

					uc := v1.NewAggregatorUseCase(mockUserSvc, mockAuthSvc, mockTodoSvc, logger)

					tt.mockSetup(mockTodoSvc, tt.id)

					pt.WithNewStep("Call GetCard", func(sCtx provider.StepCtx) {
						_, err := uc.GetCard(context.Background(), tt.id)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockTodoSvc.AssertExpectations(t)
					})
				})
			})
		}
	})
}

func TestCreateBoard(t *testing.T) {
	runner.Run(t, "TestCreateBoard", func(pt provider.T) {
		mom := &testdata.ObjectMother{}

		tests := []struct {
			name      string
			board     dto.Board
			mockSetup func(mockTodoSvc *mocks.TodoService, board dto.Board)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				board: dto.Board{
					ID:     mom.GetUUID(0),
					UserID: mom.GetUUID(1),
					Title:  "PositiveBoard",
				},
				mockSetup: func(mockTodoSvc *mocks.TodoService, board dto.Board) {
					mockTodoSvc.On("CreateBoard", context.Background(), board).Return(nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				board: dto.Board{
					ID:     mom.GetUUID(0),
					UserID: mom.GetUUID(1),
					Title:  "NegativeBoard",
				},
				mockSetup: func(mockTodoSvc *mocks.TodoService, board dto.Board) {
					mockTodoSvc.On("CreateBoard", context.Background(), board).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrCreateBoard,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockUserSvc := new(mocks.UserService)
					mockAuthSvc := new(mocks.AuthService)
					mockTodoSvc := new(mocks.TodoService)
					logger := log.NewEmptyLogger()

					uc := v1.NewAggregatorUseCase(mockUserSvc, mockAuthSvc, mockTodoSvc, logger)

					tt.mockSetup(mockTodoSvc, tt.board)

					pt.WithNewStep("Call CreateBoard", func(sCtx provider.StepCtx) {
						err := uc.CreateBoard(context.Background(), tt.board)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockTodoSvc.AssertExpectations(t)
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
			column    dto.Column
			mockSetup func(mockTodoSvc *mocks.TodoService, column dto.Column)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				column: dto.Column{
					ID:      mom.GetUUID(0),
					UserID:  mom.GetUUID(1),
					BoardID: mom.GetUUID(2),
					Title:   "PositiveColumn",
				},
				mockSetup: func(mockTodoSvc *mocks.TodoService, column dto.Column) {
					mockTodoSvc.On("CreateColumn", context.Background(), column).Return(nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				column: dto.Column{
					ID:      mom.GetUUID(0),
					UserID:  mom.GetUUID(1),
					BoardID: mom.GetUUID(2),
					Title:   "NegativeColumn",
				},
				mockSetup: func(mockTodoSvc *mocks.TodoService, column dto.Column) {
					mockTodoSvc.On("CreateColumn", context.Background(), column).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrCreateColumn,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockUserSvc := new(mocks.UserService)
					mockAuthSvc := new(mocks.AuthService)
					mockTodoSvc := new(mocks.TodoService)
					logger := log.NewEmptyLogger()

					uc := v1.NewAggregatorUseCase(mockUserSvc, mockAuthSvc, mockTodoSvc, logger)

					tt.mockSetup(mockTodoSvc, tt.column)

					pt.WithNewStep("Call CreateColumn", func(sCtx provider.StepCtx) {
						err := uc.CreateColumn(context.Background(), tt.column)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockTodoSvc.AssertExpectations(t)
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
			card      dto.Card
			mockSetup func(mockTodoSvc *mocks.TodoService, card dto.Card)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				card: dto.Card{
					ID:       mom.GetUUID(0),
					UserID:   mom.GetUUID(1),
					ColumnID: mom.GetUUID(2),
					Title:    "PositiveCard",
				},
				mockSetup: func(mockTodoSvc *mocks.TodoService, card dto.Card) {
					mockTodoSvc.On("CreateCard", context.Background(), card).Return(nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				card: dto.Card{
					ID:       mom.GetUUID(0),
					UserID:   mom.GetUUID(1),
					ColumnID: mom.GetUUID(2),
					Title:    "NegativeCard",
				},
				mockSetup: func(mockTodoSvc *mocks.TodoService, card dto.Card) {
					mockTodoSvc.On("CreateCard", context.Background(), card).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrCreateCard,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockUserSvc := new(mocks.UserService)
					mockAuthSvc := new(mocks.AuthService)
					mockTodoSvc := new(mocks.TodoService)
					logger := log.NewEmptyLogger()

					uc := v1.NewAggregatorUseCase(mockUserSvc, mockAuthSvc, mockTodoSvc, logger)

					tt.mockSetup(mockTodoSvc, tt.card)

					pt.WithNewStep("Call CreateCard", func(sCtx provider.StepCtx) {
						err := uc.CreateCard(context.Background(), tt.card)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockTodoSvc.AssertExpectations(t)
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
			board     dto.Board
			mockSetup func(mockTodoSvc *mocks.TodoService, board *dto.Board)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				board: dto.Board{
					ID:     mom.GetUUID(0),
					UserID: mom.GetUUID(1),
					Title:  "PositiveBoard",
				},
				mockSetup: func(mockTodoSvc *mocks.TodoService, board *dto.Board) {
					mockTodoSvc.On("UpdateBoard", context.Background(), board).Return(nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				board: dto.Board{
					ID:     mom.GetUUID(0),
					UserID: mom.GetUUID(1),
					Title:  "NegativeBoard",
				},
				mockSetup: func(mockTodoSvc *mocks.TodoService, board *dto.Board) {
					mockTodoSvc.On("UpdateBoard", context.Background(), board).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrUpdateBoard,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockUserSvc := new(mocks.UserService)
					mockAuthSvc := new(mocks.AuthService)
					mockTodoSvc := new(mocks.TodoService)
					logger := log.NewEmptyLogger()

					uc := v1.NewAggregatorUseCase(mockUserSvc, mockAuthSvc, mockTodoSvc, logger)

					tt.mockSetup(mockTodoSvc, &tt.board)

					pt.WithNewStep("Call UpdateBoard", func(sCtx provider.StepCtx) {
						err := uc.UpdateBoard(context.Background(), &tt.board)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockTodoSvc.AssertExpectations(t)
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
			column    dto.Column
			mockSetup func(mockTodoSvc *mocks.TodoService, column *dto.Column)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				column: dto.Column{
					ID:      mom.GetUUID(0),
					UserID:  mom.GetUUID(1),
					BoardID: mom.GetUUID(2),
					Title:   "PositiveColumn",
				},
				mockSetup: func(mockTodoSvc *mocks.TodoService, column *dto.Column) {
					mockTodoSvc.On("UpdateColumn", context.Background(), column).Return(nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				column: dto.Column{
					ID:      mom.GetUUID(0),
					UserID:  mom.GetUUID(1),
					BoardID: mom.GetUUID(2),
					Title:   "NegativeColumn",
				},
				mockSetup: func(mockTodoSvc *mocks.TodoService, column *dto.Column) {
					mockTodoSvc.On("UpdateColumn", context.Background(), column).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrUpdateColumn,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockUserSvc := new(mocks.UserService)
					mockAuthSvc := new(mocks.AuthService)
					mockTodoSvc := new(mocks.TodoService)
					logger := log.NewEmptyLogger()

					uc := v1.NewAggregatorUseCase(mockUserSvc, mockAuthSvc, mockTodoSvc, logger)

					tt.mockSetup(mockTodoSvc, &tt.column)

					pt.WithNewStep("Call UpdateColumn", func(sCtx provider.StepCtx) {
						err := uc.UpdateColumn(context.Background(), &tt.column)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockTodoSvc.AssertExpectations(t)
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
			card      dto.Card
			mockSetup func(mockTodoSvc *mocks.TodoService, card *dto.Card)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				card: dto.Card{
					ID:       mom.GetUUID(0),
					UserID:   mom.GetUUID(1),
					ColumnID: mom.GetUUID(2),
					Title:    "PositiveCard",
				},
				mockSetup: func(mockTodoSvc *mocks.TodoService, card *dto.Card) {
					mockTodoSvc.On("UpdateCard", context.Background(), card).Return(nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				card: dto.Card{
					ID:       mom.GetUUID(0),
					UserID:   mom.GetUUID(1),
					ColumnID: mom.GetUUID(2),
					Title:    "NegativeCard",
				},
				mockSetup: func(mockTodoSvc *mocks.TodoService, card *dto.Card) {
					mockTodoSvc.On("UpdateCard", context.Background(), card).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrUpdateCard,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockUserSvc := new(mocks.UserService)
					mockAuthSvc := new(mocks.AuthService)
					mockTodoSvc := new(mocks.TodoService)
					logger := log.NewEmptyLogger()

					uc := v1.NewAggregatorUseCase(mockUserSvc, mockAuthSvc, mockTodoSvc, logger)

					tt.mockSetup(mockTodoSvc, &tt.card)

					pt.WithNewStep("Call UpdateCard", func(sCtx provider.StepCtx) {
						err := uc.UpdateCard(context.Background(), &tt.card)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockTodoSvc.AssertExpectations(t)
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
			id        string
			mockSetup func(mockTodoSvc *mocks.TodoService, id string)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				id:   mom.GetUUID(0).String(),
				mockSetup: func(mockTodoSvc *mocks.TodoService, id string) {
					mockTodoSvc.On("DeleteBoard", context.Background(), id).Return(nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				id:   mom.GetUUID(0).String(),
				mockSetup: func(mockTodoSvc *mocks.TodoService, id string) {
					mockTodoSvc.On("DeleteBoard", context.Background(), id).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrDeleteBoard,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockUserSvc := new(mocks.UserService)
					mockAuthSvc := new(mocks.AuthService)
					mockTodoSvc := new(mocks.TodoService)
					logger := log.NewEmptyLogger()

					uc := v1.NewAggregatorUseCase(mockUserSvc, mockAuthSvc, mockTodoSvc, logger)

					tt.mockSetup(mockTodoSvc, tt.id)

					pt.WithNewStep("Call DeleteBoard", func(sCtx provider.StepCtx) {
						err := uc.DeleteBoard(context.Background(), tt.id)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockTodoSvc.AssertExpectations(t)
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
			id        string
			mockSetup func(mockTodoSvc *mocks.TodoService, id string)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				id:   mom.GetUUID(0).String(),
				mockSetup: func(mockTodoSvc *mocks.TodoService, id string) {
					mockTodoSvc.On("DeleteColumn", context.Background(), id).Return(nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				id:   mom.GetUUID(0).String(),
				mockSetup: func(mockTodoSvc *mocks.TodoService, id string) {
					mockTodoSvc.On("DeleteColumn", context.Background(), id).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrDeleteColumn,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockUserSvc := new(mocks.UserService)
					mockAuthSvc := new(mocks.AuthService)
					mockTodoSvc := new(mocks.TodoService)
					logger := log.NewEmptyLogger()

					uc := v1.NewAggregatorUseCase(mockUserSvc, mockAuthSvc, mockTodoSvc, logger)

					tt.mockSetup(mockTodoSvc, tt.id)

					pt.WithNewStep("Call DeleteColumn", func(sCtx provider.StepCtx) {
						err := uc.DeleteColumn(context.Background(), tt.id)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockTodoSvc.AssertExpectations(t)
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
			id        string
			mockSetup func(mockTodoSvc *mocks.TodoService, id string)
			wantErr   bool
			err       error
		}{
			{
				name: "positive",
				id:   mom.GetUUID(0).String(),
				mockSetup: func(mockTodoSvc *mocks.TodoService, id string) {
					mockTodoSvc.On("DeleteCard", context.Background(), id).Return(nil)
				},
				wantErr: false,
			},
			{
				name: "negative",
				id:   mom.GetUUID(0).String(),
				mockSetup: func(mockTodoSvc *mocks.TodoService, id string) {
					mockTodoSvc.On("DeleteCard", context.Background(), id).Return(errors.New(""))
				},
				wantErr: true,
				err:     v1.ErrDeleteCard,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				runner.Run(t, tt.name, func(pt provider.T) {
					mockUserSvc := new(mocks.UserService)
					mockAuthSvc := new(mocks.AuthService)
					mockTodoSvc := new(mocks.TodoService)
					logger := log.NewEmptyLogger()

					uc := v1.NewAggregatorUseCase(mockUserSvc, mockAuthSvc, mockTodoSvc, logger)

					tt.mockSetup(mockTodoSvc, tt.id)

					pt.WithNewStep("Call DeleteCard", func(sCtx provider.StepCtx) {
						err := uc.DeleteCard(context.Background(), tt.id)

						if tt.wantErr {
							sCtx.Assert().Error(err, "Expected error")
							sCtx.Assert().ErrorIs(err, tt.err)
						} else {
							sCtx.Assert().NoError(err, "Expected no error")
						}

						mockTodoSvc.AssertExpectations(t)
					})
				})
			})
		}
	})
}

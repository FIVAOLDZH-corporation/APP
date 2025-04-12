package usecase

import (
	"context"
	"time"
	"todo/internal/entity"

	"github.com/google/uuid"
)

type TodoUseCase interface {
	CreateBoard(ctx context.Context, board *entity.Board) error
	CreateColumn(ctx context.Context, column *entity.Column) error
	CreateCard(ctx context.Context, card *entity.Card) error

	GetBoardByID(ctx context.Context, id uuid.UUID) (*entity.Board, error)
	GetColumnByID(ctx context.Context, id uuid.UUID) (*entity.Column, error)
	GetCardByID(ctx context.Context, id uuid.UUID) (*entity.Card, error)
	GetBoardsByUser(ctx context.Context, userID uuid.UUID, limit, offset int) ([]entity.Board, error)
	GetColumnsByBoard(ctx context.Context, boardID uuid.UUID, limit, offset int) ([]entity.Column, error)
	GetCardsByColumn(ctx context.Context, columnID uuid.UUID, limit, offset int) ([]entity.Card, error)
	GetNewCards(ctx context.Context, from, to time.Time) ([]entity.Card, error)

	UpdateBoard(ctx context.Context, board *entity.Board) error
	UpdateColumn(ctx context.Context, column *entity.Column) error
	UpdateCard(ctx context.Context, card *entity.Card) error

	DeleteBoard(ctx context.Context, id uuid.UUID) error
	DeleteColumn(ctx context.Context, id uuid.UUID) error
	DeleteCard(ctx context.Context, id uuid.UUID) error
}

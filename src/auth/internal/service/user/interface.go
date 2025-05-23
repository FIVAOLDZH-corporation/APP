package user

import (
	"auth/internal/dto"
	"context"
)

type UserService interface {
	CreateUser(ctx context.Context, username, email, password string) error
	GetUserByEmail(ctx context.Context, email string) (*dto.User, error)
	UpdatePassword(ctx context.Context, userID, newPassword string) error
	UpdateStatusVerified(ctx context.Context, userID string, status bool) error
}

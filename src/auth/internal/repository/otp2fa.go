package repository

import (
	"context"
)

type OTP2FARepository interface {
	SaveSecret(ctx context.Context, userID, secret string) error
	GetSecret(ctx context.Context, userID string) (string, error)
	Enable(ctx context.Context, userID string) error
	Disable(ctx context.Context, userID string) error
	Enabled(ctx context.Context, userID string) (bool, error)
}

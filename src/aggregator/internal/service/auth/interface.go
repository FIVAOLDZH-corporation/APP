package auth

import (
	"aggregator/internal/dto"
	"context"
)

type AuthService interface {
	Register(ctx context.Context, username, email, password string) (*dto.Tokens, error)
	Login(ctx context.Context, email, password string) (*dto.Tokens, error)
	Refresh(ctx context.Context, refreshToken string) (*dto.RefreshResponse, error)
	ValidateToken(ctx context.Context, token string) (*dto.ValidateTokenResponse, error)
	Logout(ctx context.Context, refreshToken string) error
	VerifyEmail(ctx context.Context, email, code string) error

	LoginOTP(ctx context.Context, email, otp string) (*dto.Tokens, error)
	GenerateOTPSecret(ctx context.Context, email string) (string, error)
	Enable2FA(ctx context.Context, email string) error
	Disable2FA(ctx context.Context, email string) error
	ValidateOTP(ctx context.Context, email, otp string) (bool, error)
	Enabled2FA(ctx context.Context, email string) (bool, error)
	UpdatePassword2FA(ctx context.Context, email, oldPassword, newPassword, otp string) error
}

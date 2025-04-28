package usecase

import (
	"auth/internal/dto"
	"context"
)

type AuthUsecase interface {
	Register(ctx context.Context, username, email, password string) (*dto.Tokens, error)
	Login(ctx context.Context, email, password string) (*dto.Tokens, error)
	LoginOTP(ctx context.Context, email, otp string) (*dto.Tokens, error)
	Refresh(ctx context.Context, refreshToken string) (*dto.RefreshTokenResponse, error)
	ValidateToken(ctx context.Context, token string) (string, string, error)
	GenerateOTPSecret(ctx context.Context, email string) (string, error)
	Enable2FA(ctx context.Context, email string) error
	Disable2FA(ctx context.Context, email string) error
	ValidateOTP(ctx context.Context, email, otp string) (bool, error)
	Enabled2FA(ctx context.Context, email string) (bool, error)
	Logout(ctx context.Context, refreshToken string) error
	UpdatePassword2FA(ctx context.Context, email, oldPassword, newPassword, otp string) error
	VerifyEmail(ctx context.Context, email string, code string) error
}

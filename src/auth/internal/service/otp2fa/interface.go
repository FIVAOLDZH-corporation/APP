package otp2fa

import "context"

type OTP2FAService interface {
	GenerateSecret(ctx context.Context, userID string) (string, error)
	Enable2FA(ctx context.Context, userID string) error
	Disable2FA(ctx context.Context, userID string) error
	ValidateOTP(ctx context.Context, userID, otp string) (bool, error)
	Enabled2FA(ctx context.Context, userID string) bool
}

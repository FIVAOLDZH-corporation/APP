package otp2fa

import (
	"auth/internal/common/logger"
	"auth/internal/repository"
	"context"
	"errors"
	"fmt"

	"github.com/pquerna/otp/totp"
)

var (
	ErrGenerateSecret error = errors.New("failed to generate secret")
	ErrSaveSecret     error = errors.New("failed to save secret")
	ErrEnable2FA      error = errors.New("failed to enable 2FA")
	ErrDisable2FA     error = errors.New("failed to disable 2FA")
	ErrValidateOTP    error = errors.New("failed to validate OTP")
	ErrGetSecret      error = errors.New("failed to get secret from repo")
	ErrEnabled2FA     error = errors.New("failed to check if 2FA is enabled")
)

type OTP2FAService struct {
	repo repository.OTP2FARepository
	log  logger.Logger
}

func NewOTP2FAService(repo repository.OTP2FARepository, log logger.Logger) *OTP2FAService {
	return &OTP2FAService{repo: repo, log: log}
}

func (s *OTP2FAService) GenerateSecret(ctx context.Context, userID string) (string, error) {
	header := "GenerateSecret: "

	s.log.Info(ctx, header+"Generating TOTP")

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Runov ToDo App",
		AccountName: userID,
	})

	if err != nil {
		info := "Failed to generate TOTP"
		s.log.Error(ctx, header+info, "err", err.Error())
		return "", fmt.Errorf(header+info+": %w", ErrGenerateSecret)
	}

	secret := key.Secret()

	s.log.Info(ctx, header+"Generated secret", "secret", secret)

	s.log.Info(ctx, header+"Making request to repo (SaveSecret)", "secret", secret)

	err = s.repo.SaveSecret(ctx, userID, secret)

	if err != nil {
		info := "Failed to save secret"
		s.log.Error(ctx, header+info, "err", err.Error())
		return "", fmt.Errorf(header+info+": %w", ErrSaveSecret)
	}

	s.log.Info(ctx, header+"Successfully saved secret")

	return secret, nil
}

func (s *OTP2FAService) Enable2FA(ctx context.Context, userID string) error {
	header := "Enable2FA: "

	s.log.Info(ctx, header+"Making request to repo (Enable)", "userID", userID)

	err := s.repo.Enable(ctx, userID)

	if err != nil {
		info := "Failed to enable 2FA"
		s.log.Error(ctx, header+info, "err", err.Error())
		return fmt.Errorf(header+info+": %w", ErrEnable2FA)
	}

	s.log.Info(ctx, header+"Successfully enabled")

	return nil
}

func (s *OTP2FAService) Disable2FA(ctx context.Context, userID string) error {
	header := "Disable2FA: "

	s.log.Info(ctx, header+"Making request to repo (Disable)", "userID", userID)

	err := s.repo.Disable(ctx, userID)

	if err != nil {
		info := "Failed to disable 2FA"
		s.log.Error(ctx, header+info, "err", err.Error())
		return fmt.Errorf(header+info+": %w", ErrDisable2FA)
	}

	s.log.Info(ctx, header+"Successfully disabled")

	return nil
}

func (s *OTP2FAService) ValidateOTP(ctx context.Context, userID, otp string) (bool, error) {
	header := "ValidateOTP: "

	s.log.Info(ctx, header+"Making request to repo (GetSecret)", "userID", userID)

	secret, err := s.repo.GetSecret(ctx, userID)

	if err != nil {
		info := "Failed to get secret from repo"
		s.log.Error(ctx, header+info, "err", err.Error())
		return false, fmt.Errorf(header+info+": %w", ErrGetSecret)
	}

	isValid := totp.Validate(otp, secret)

	s.log.Info(ctx, header+"Validation result", "isValid", isValid)

	return isValid, nil
}

func (s *OTP2FAService) Enabled2FA(ctx context.Context, userID string) bool {
	header := "Enabled2FA: "

	s.log.Info(ctx, header+"Making request to repo (Enabled)", "userID", userID)

	enabled, err := s.repo.Enabled(ctx, userID)

	if err == nil {
		s.log.Info(ctx, header+"User has 2FA; Enabled status", "enabled", enabled)
	} else {
		// XXX: Assume record doesn't exist on error
		enabled = false
		s.log.Info(ctx, header+"User has never set 2FA; Disabled")
	}

	return enabled
}

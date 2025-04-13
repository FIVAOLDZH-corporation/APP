package sqlx

import (
	"auth/internal/repository"
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type SQLXOTP2FARepository struct {
	db *sqlx.DB
}

func NewSQLXOTP2FARepository(db *sqlx.DB) *SQLXOTP2FARepository {
	return &SQLXOTP2FARepository{
		db: db,
	}
}

func (r *SQLXOTP2FARepository) SaveSecret(ctx context.Context, userID, secret string) error {
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		return err
	}

	// HACK: Meh, should not be done on repository level
	repoOTP2FA := repository.OTP2FA{
		ID:        uuid.New(),
		UserID:    userUUID,
		Secret:    secret,
		Enabled:   false,
		CreatedAt: time.Now(),
	}

	query := `
        INSERT INTO otp_2fa (id, user_id, secret, enabled, created_at)
		VALUES (:id, :user_id, :secret, :enabled, :created_at)
    `

	_, err = r.db.NamedExecContext(ctx, query, repoOTP2FA)
	if err != nil {
		return err
	}

	return nil
}

func (r *SQLXOTP2FARepository) GetSecret(ctx context.Context, userID string) (string, error) {
	query := `SELECT secret FROM otp_2fa WHERE user_id = $1`

	var secret string

	err := r.db.GetContext(ctx, &secret, query, userID)
	if err != nil {
		return "", err
	}

	return secret, nil
}

func (r *SQLXOTP2FARepository) Enable(ctx context.Context, userID string) error {
	query := `UPDATE otp_2fa SET enabled = true WHERE user_id = $1`

	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return err
	}

	return nil
}

func (r *SQLXOTP2FARepository) Disable(ctx context.Context, userID string) error {
	query := `UPDATE otp_2fa SET enabled = false WHERE user_id = $1`

	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return err
	}

	return nil
}

func (r *SQLXOTP2FARepository) Enabled(ctx context.Context, userID string) (bool, error) {
	query := `SELECT enabled FROM otp_2fa WHERE user_id = $1`

	var enabled bool

	err := r.db.GetContext(ctx, &enabled, query, userID)
	if err != nil {
		return false, err
	}

	return enabled, nil
}

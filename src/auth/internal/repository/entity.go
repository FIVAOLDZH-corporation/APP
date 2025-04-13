package repository

import (
	"auth/internal/entity"
	"time"

	"github.com/google/uuid"
)

type Token struct {
	ID        uuid.UUID `db:"id"`
	UserID    uuid.UUID `db:"user_id"`
	Token     string    `db:"token"`
	CreatedAt time.Time `db:"created_at"`
}

type OTP2FA struct {
	ID        uuid.UUID `db:"id"`
	UserID    uuid.UUID `db:"user_id"`
	Secret    string    `db:"secret"`
	Enabled   bool      `db:"enabled"`
	CreatedAt time.Time `db:"created_at"`
}

func RepoToken(e entity.Token) Token {
	return Token{
		ID:        e.ID,
		UserID:    e.UserID,
		Token:     e.Token,
		CreatedAt: e.CreatedAt,
	}
}

func RepoOTP2FA(e entity.OTP2FA) OTP2FA {
	return OTP2FA{
		ID:        e.ID,
		UserID:    e.UserID,
		Secret:    e.Secret,
		Enabled:   e.Enabled,
		CreatedAt: e.CreatedAt,
	}
}

func TokenToEntity(r Token) entity.Token {
	return entity.Token{
		ID:        r.ID,
		UserID:    r.UserID,
		Token:     r.Token,
		CreatedAt: r.CreatedAt,
	}
}

func OTP2FAToEntity(r OTP2FA) entity.OTP2FA {
	return entity.OTP2FA{
		ID:        r.ID,
		UserID:    r.UserID,
		Secret:    r.Secret,
		Enabled:   r.Enabled,
		CreatedAt: r.CreatedAt,
	}
}

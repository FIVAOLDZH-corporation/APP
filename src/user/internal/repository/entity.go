package repository

import (
	"time"
	"user/internal/entity"

	"github.com/google/uuid"
)

type User struct {
	ID            uuid.UUID `db:"id"            bson:"_id,omitempty"`
	Username      string    `db:"username"      bson:"username"`
	Email         string    `db:"email"         bson:"email"`
	Role          string    `db:"role"          bson:"role"`
	PasswordHash  string    `db:"password_hash" bson:"password_hash"`
	EmailVerified bool      `db:"email_verified" bson:"email_verified"`
	CreatedAt     time.Time `db:"created_at"    bson:"created_at"`
	UpdatedAt     time.Time `db:"updated_at"    bson:"updated_at"`
}

func RepoUser(e entity.User) User {
	return User{
		ID:            e.ID,
		Username:      e.Username,
		Email:         e.Email,
		Role:          e.Role,
		PasswordHash:  e.PasswordHash,
		EmailVerified: e.EmailVerified,
		CreatedAt:     e.CreatedAt,
		UpdatedAt:     e.UpdatedAt,
	}
}

func UserToEntity(r User) entity.User {
	return entity.User{
		ID:            r.ID,
		Username:      r.Username,
		Email:         r.Email,
		Role:          r.Role,
		PasswordHash:  r.PasswordHash,
		EmailVerified: r.EmailVerified,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
	}
}

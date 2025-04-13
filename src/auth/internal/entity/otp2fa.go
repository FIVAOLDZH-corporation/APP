package entity

import (
	"time"

	"github.com/google/uuid"
)

type OTP2FA struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Secret    string
	Enabled   bool
	CreatedAt time.Time
}

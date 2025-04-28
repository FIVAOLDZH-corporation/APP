package dto

import "github.com/google/uuid"

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type User struct {
	ID            uuid.UUID `json:"id"`
	Username      string    `json:"username"`
	Email         string    `json:"email"`
	Role          string    `json:"role"`
	EmailVerified bool      `json:"email_verified"`
	PasswordHash  string    `json:"password_hash"`
}

type UpdatePasswordRequest struct {
	ID       uuid.UUID `json:"id"`
	Password string    `json:"password" validate:"required"`
}

type UpdateStatusVerifiedRequest struct {
	ID            uuid.UUID `json:"id"`
	EmailVerified bool      `json:"email_verified"`
}

type VerifyEmailRequest struct {
	Email string `json:"email" validate:"required,email"`
	Code  string `json:"code" validate:"required"`
}

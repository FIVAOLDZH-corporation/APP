package testdata

import (
	"time"
	"user/internal/entity"

	"github.com/google/uuid"
)

type UserBuilder struct {
	user entity.User
}

func NewUserBuilder() *UserBuilder {
	return &UserBuilder{
		user: entity.User{},
	}
}

// func NewUserBuilder(user entity.User) *UserBuilder {
// 	return &UserBuilder{user}
// }

func (b *UserBuilder) WithUsername(username string) *UserBuilder {
	b.user.Username = username
	return b
}

func (b *UserBuilder) WithEmail(email string) *UserBuilder {
	b.user.Email = email
	return b
}

func (b *UserBuilder) WithPassword(password string) *UserBuilder {
	b.user.PasswordHash = password
	return b
}

func (b *UserBuilder) WithID(id uuid.UUID) *UserBuilder {
	b.user.ID = id
	return b
}

func (b *UserBuilder) WithCreatedAt(createdAt time.Time) *UserBuilder {
	b.user.CreatedAt = createdAt
	return b
}

func (b *UserBuilder) WithUpdatedAt(updatedAt time.Time) *UserBuilder {
	b.user.UpdatedAt = updatedAt
	return b
}

func (b *UserBuilder) Build() entity.User {
	return b.user
}

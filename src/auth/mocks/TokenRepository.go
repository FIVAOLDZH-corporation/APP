// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	entity "auth/internal/entity"
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// TokenRepository is an autogenerated mock type for the TokenRepository type
type TokenRepository struct {
	mock.Mock
}

// Delete provides a mock function with given fields: ctx, tokenID
func (_m *TokenRepository) Delete(ctx context.Context, tokenID string) error {
	ret := _m.Called(ctx, tokenID)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, tokenID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FindByToken provides a mock function with given fields: ctx, token
func (_m *TokenRepository) FindByToken(ctx context.Context, token string) (*entity.Token, error) {
	ret := _m.Called(ctx, token)

	if len(ret) == 0 {
		panic("no return value specified for FindByToken")
	}

	var r0 *entity.Token
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*entity.Token, error)); ok {
		return rf(ctx, token)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *entity.Token); ok {
		r0 = rf(ctx, token)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*entity.Token)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Save provides a mock function with given fields: ctx, token
func (_m *TokenRepository) Save(ctx context.Context, token *entity.Token) error {
	ret := _m.Called(ctx, token)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *entity.Token) error); ok {
		r0 = rf(ctx, token)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewTokenRepository creates a new instance of TokenRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewTokenRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *TokenRepository {
	mock := &TokenRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

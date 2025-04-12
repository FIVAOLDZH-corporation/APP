package testdata

import (
	"time"
	"user/internal/entity"
	"user/internal/repository"

	"github.com/google/uuid"
)

type UserObjectMother struct{}

var uuidsPool = []string{
	"86b5682f-f066-4012-a557-f894a4d88851",
	"8a62bda8-3f39-4d2a-93de-5c08bf314667",
	"b2ce56e2-d117-444c-9fbd-6fa9759173c5",
	"44970116-f820-4b8f-9fe1-87c405db05ab",
	"5a78ebdf-9b0c-4f7d-95d5-03c4a4761eaf",
	"80183ed4-fbef-4783-a4af-41308908ec78",
	"92c8c730-72d7-4cd2-af21-276ff241f7bb",
	"e61c5f69-e10a-4268-9c6c-864bcc789f67",
	"4c5fc5f9-4fa9-4fc5-b359-5e84aebc9027",
	"2f7e3723-ad62-47e0-9018-8ec7e5293e54",
	"07bd2e0c-3b0d-49e7-9c1a-b382d02c943f",
	"8ca8e135-a2f2-4a7d-8a49-8de97c229d9d",
	"9bacff1d-53f8-451e-8528-cb8d62375c48",
	"9666db49-6dc6-48b2-8d31-e74d237f96c1",
	"457f559c-61ab-4a79-b93a-6a9f22535ba4",
	"c069e7dc-8616-4f1a-a3fc-7f3e6aaac03c",
	"ffa8d00c-b741-4260-828c-80698f23eb8d",
	"673d3b33-49fe-45d2-af62-c7d96b6ea431",
	"d30d3c26-45f4-45bf-a82b-aacda537d1fc",
	"d0f33e39-6d6e-44c3-8725-9d8127355001",
}

func (u *UserObjectMother) GetUUID(index int) uuid.UUID {
	id, _ := uuid.Parse(uuidsPool[index])
	return id
}

func (u *UserObjectMother) ValidUser() entity.User {
	return entity.User{
		ID:           uuid.New(),
		Username:     "ValidUser",
		Email:        "valid@example.com",
		PasswordHash: "Password@123",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}

func (u *UserObjectMother) InvalidEmailUser() entity.User {
	return entity.User{
		ID:           uuid.New(),
		Username:     "InValidUser",
		Email:        "invalid-email",
		PasswordHash: "Password@123",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}

func (u *UserObjectMother) PositiveUsernameFilter() repository.UserFilter {
	username := "PositiveUser"
	return repository.UserFilter{
		Username: &username,
	}
}

func (u *UserObjectMother) NegativeUsernameFilter() repository.UserFilter {
	username := "NegativeUser"
	return repository.UserFilter{
		Username: &username,
	}
}

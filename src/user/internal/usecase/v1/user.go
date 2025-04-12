package v1

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
	"user/internal/common/logger"
	"user/internal/entity"
	"user/internal/repository"
	"user/internal/usecase"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidFromTo         = errors.New("<<to>> date should be not less than <<from>>")
	ErrInvalidEmailFormat    = errors.New("invalid email format")
	ErrInvalidUsernameFormat = errors.New("invalid username format")
	ErrInvalidPasswordFormat = errors.New("invalid password format")
	ErrHashPassword          = errors.New("unable to hash password")
	ErrCreateUser            = errors.New("failed to create user")
	ErrGetUserByID           = errors.New("failed to get user by id")
	ErrGetUserByUsername     = errors.New("failed to get user by username")
	ErrGetUserByEmail        = errors.New("failed to get user by email")
	ErrGetUsers              = errors.New("failed to get users")
	ErrGetUsersBatch         = errors.New("failed to get users batch")
	ErrGetNewUsers           = errors.New("failed to get new users")
	ErrUserNotExist          = errors.New("user doesn't exist")
	ErrUpdateUser            = errors.New("failed to update user")
	ErrDeleteUser            = errors.New("failed to delete user")
	ErrNegativeLimitOrOffset = errors.New("limit and offset can't be negative")
	ErrLimitNotPositive      = errors.New("limit should be greater than zero")
)

type userUseCase struct {
	repo repository.UserRepository
	log  logger.Logger
}

func NewUserUseCase(repo repository.UserRepository, log logger.Logger) usecase.UserUseCase {
	return &userUseCase{
		repo: repo,
		log:  log,
	}
}

func (u *userUseCase) CreateUser(ctx context.Context, user entity.User) error {
	header := "CreateUser: "
	u.log.Info(ctx, header+"Usecase called; Validating email", "user", user)

	err := isValidEmail(user.Email)

	if err != nil {
		u.log.Info(ctx, header+"Invalid email", "email", user.Email, "err", err.Error())
		return err
	}

	u.log.Info(ctx, header+"Email is valid; validating username")

	err = isValidUsername(user.Username)

	if err != nil {
		u.log.Info(ctx, header+"Invalid username", "username", user.Username, "err", err.Error())
		return err
	}

	u.log.Info(ctx, header+"Username is valid; validating password")

	// TODO: Maybe move password validation to auth service,
	// and deal only with hashes in user service.
	err = validatePassword(user.PasswordHash) // NOTE: Plain password, unencrypted initially

	if err != nil {
		u.log.Info(ctx, header+"Invalid password", "password", user.PasswordHash)
		return err
	}

	u.log.Info(ctx, header+"Password is valid; hashing password")

	hashedPassword, err := hashPassword(user.PasswordHash)

	if err != nil {
		info := "Unable to hash password"
		u.log.Error(ctx, header+info, "password", user.PasswordHash, "err", err.Error())
		return fmt.Errorf(header+info+": %w", ErrHashPassword)
	}

	user.PasswordHash = hashedPassword

	user.ID = uuid.New()
	user.Role = "user"
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	u.log.Info(ctx, header+"User has been assigned uuid, making request to repo", "uuid", user.ID)

	err = u.repo.CreateUser(ctx, &user)

	if err != nil {
		info := "Failed to create user"
		u.log.Error(ctx, header+info, "err", err.Error())
		return fmt.Errorf(header+info+": %w", ErrCreateUser)
	}

	u.log.Info(ctx, header+"User successfully created")

	return nil
}

func isValidEmail(email string) error {
	pattern := `^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$`
	re := regexp.MustCompile(pattern)

	if !re.MatchString(email) {
		return fmt.Errorf("%w: email doesn't match regex %s", ErrInvalidEmailFormat, pattern)
	}

	return nil
}

func isValidUsername(username string) error {
	pattern := `^[a-zA-Z][a-zA-Z0-9_]{4,}$`
	re := regexp.MustCompile(pattern)

	if !re.MatchString(username) {
		return fmt.Errorf("%w: username doesn't match regex %s", ErrInvalidUsernameFormat, pattern)
	}

	return nil
}

func validatePassword(password string) error {
	if len(password) < 8 || len(password) > 32 {
		return fmt.Errorf("%w: password must be between 8 and 32 characters long", ErrInvalidPasswordFormat)
	}

	hasUpperCase := regexp.MustCompile(`[A-Z]`).MatchString(password)
	if !hasUpperCase {
		return fmt.Errorf("%w: password must contain at least one uppercase letter", ErrInvalidPasswordFormat)
	}

	hasLowerCase := regexp.MustCompile(`[a-z]`).MatchString(password)
	if !hasLowerCase {
		return fmt.Errorf("%w: password must contain at least one lowercase letter", ErrInvalidPasswordFormat)
	}

	hasDigit := regexp.MustCompile(`[0-9]`).MatchString(password)
	if !hasDigit {
		return fmt.Errorf("%w: password must contain at least one digit", ErrInvalidPasswordFormat)
	}

	hasSpecialChar := regexp.MustCompile(`[!@#~$%^&*(),.?":{}|<>]`).MatchString(password)
	if !hasSpecialChar {
		return fmt.Errorf("%w: password must contain at least one special character", ErrInvalidPasswordFormat)
	}

	return nil
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func (u *userUseCase) GetUserByID(ctx context.Context, id uuid.UUID) (*entity.User, error) {
	header := "GetUserByID: "

	u.log.Info(ctx, header+"Usecase called; Making request to repo", "id", id)

	user, err := u.repo.GetUserByID(ctx, id)

	if err != nil {
		info := "Failed to get user by id"
		u.log.Error(ctx, header+info, "err", err.Error())
		return nil, fmt.Errorf(header+info+": %w", ErrGetUserByID)
	}

	u.log.Info(ctx, "Got user", "user", user)

	return user, nil
}

func (u *userUseCase) GetUserByUsername(ctx context.Context, username string) (*entity.User, error) {
	header := "GetUserByUsername: "

	u.log.Info(ctx, header+"Usecase called; Making request to repo", "username", username)

	user, err := u.repo.GetUserByUsername(ctx, username)

	if err != nil {
		info := "Failed to get user by username"
		u.log.Error(ctx, header+info, "err", err.Error())
		return nil, fmt.Errorf(header+info+": %w", ErrGetUserByUsername)
	}

	u.log.Info(ctx, "Got user", "user", user)

	return user, nil
}

func (u *userUseCase) GetUserByEmail(ctx context.Context, email string) (*entity.User, error) {
	header := "GetUserByEmail: "

	u.log.Info(ctx, header+"Usecase called; Making request to repo", "email", email)

	user, err := u.repo.GetUserByEmail(ctx, email)

	if err != nil {
		info := "Failed to get user by email"
		u.log.Error(ctx, header+info, "err", err.Error())
		return nil, fmt.Errorf(header+info+": %w", ErrGetUserByEmail)
	}

	u.log.Info(ctx, "Got user", "user", user)

	return user, nil
}

func (u *userUseCase) GetUsers(ctx context.Context, filter repository.UserFilter) ([]entity.User, error) {
	header := "GetUsers: "

	u.log.Info(ctx, header+"Usecase called; Making request to repo", "filter", filter)

	users, err := u.repo.GetUsers(ctx, filter)

	if err != nil {
		info := "Failed to get users"
		u.log.Error(ctx, header+info, "err", err.Error())
		return nil, fmt.Errorf(header+info+": %w", ErrGetUsers)
	}

	u.log.Info(ctx, header+"Got users", "users", users)

	return users, nil
}

func (u *userUseCase) GetUsersBatch(ctx context.Context, limit, offset int) ([]entity.User, error) {
	header := "GetUsersBatch: "

	u.log.Info(ctx, header+"Usecase called; Validating limit and offset", "limit", limit, "offset", offset)

	if limit < 0 || offset < 0 {
		info := "Limit and offset can't be negative"
		u.log.Info(ctx, header+info, "limit", limit, "offset", offset)
		return nil, ErrNegativeLimitOrOffset
	} else if limit == 0 {
		info := "Limit should be greater than zero"
		u.log.Info(ctx, header+info, "limit", limit, "offset", offset)
		return nil, ErrLimitNotPositive
	}

	u.log.Info(ctx, header+"Successful validation; Making request to repo", "limit", limit, "offset", offset)

	users, err := u.repo.GetUsersBatch(ctx, limit, offset)

	if err != nil {
		info := "Failed to get users batch"
		u.log.Error(ctx, header+info, "err", err.Error())
		return nil, fmt.Errorf(header+info+": %w", ErrGetUsersBatch)
	}

	u.log.Info(ctx, header+"Got users", "users", users)

	return users, nil
}

func (u *userUseCase) GetNewUsers(ctx context.Context, from time.Time, to time.Time) ([]entity.User, error) {
	header := "GetNewUsers: "

	u.log.Info(ctx, header+"Usecase called; Validating from, to", "from", from, "to", to)

	if from.Unix() > to.Unix() {
		err := ErrInvalidFromTo
		u.log.Info(ctx, header+"Bad from, to", "err", err.Error())
		return nil, err
	}

	u.log.Info(ctx, header+"Successful validation; Making request to repo", "from", from, "to", to)

	users, err := u.repo.GetNewUsers(ctx, from, to)

	if err != nil {
		info := "Failed to get new users"
		u.log.Error(ctx, header+info, "err", err.Error())
		return nil, fmt.Errorf(header+info+": %w", ErrGetNewUsers)
	}

	u.log.Info(ctx, header+"Got users", "users", users)

	return users, nil
}

func (u *userUseCase) UpdateUser(ctx context.Context, user *entity.User) (*entity.User, error) {
	header := "UpdateUser: "

	u.log.Info(ctx, header+"Usecase called", "user", user)

	u.log.Info(ctx, header+"Making request to repo (GetUserByID) to check if user exits", "id", user.ID)

	existingUser, err := u.repo.GetUserByID(ctx, user.ID)

	if err != nil {
		info := "Failed to get user by id"
		u.log.Error(ctx, header+info, "err", err.Error())
		return nil, fmt.Errorf(header+info+": %w", ErrGetUserByID)
	}

	if existingUser == nil {
		info := "User does not exist"
		u.log.Error(ctx, header+info)
		return nil, ErrUserNotExist
	}

	// XXX: DRY
	err = isValidEmail(user.Email)

	if err != nil {
		u.log.Info(ctx, header+"Invalid email", "email", user.Email, "err", err.Error())
		return nil, err
	}

	u.log.Info(ctx, header+"Email is valid; validating username")

	err = isValidUsername(user.Username)

	if err != nil {
		u.log.Info(ctx, header+"Invalid username", "username", user.Username, "err", err.Error())
		return nil, err
	}

	u.log.Info(ctx, header+"Username is valid; validating password")

	// TODO: Maybe move password validation to auth service,
	// and deal only with hashes in user service.
	err = validatePassword(user.PasswordHash) // NOTE: Plain password, unencrypted initially

	if err != nil {
		u.log.Info(ctx, header+"Invalid password", "password", user.PasswordHash)
		return nil, err
	}

	u.log.Info(ctx, header+"Password is valid; hashing password")

	hashedPassword, err := hashPassword(user.PasswordHash)

	if err != nil {
		info := "Unable to hash password"
		u.log.Error(ctx, header+info, "password", user.PasswordHash, "err", err.Error())
		return nil, fmt.Errorf(header+info+": %w", ErrHashPassword)
	}

	user.PasswordHash = hashedPassword
	// XXX: end of DRY

	user.UpdatedAt = time.Now()

	u.log.Info(ctx, header+"User exists. Making request to repo", "existingUser", existingUser, "user", user)

	err = u.repo.UpdateUser(ctx, user)

	if err != nil {
		info := "Failed to update user"
		u.log.Error(ctx, header+info, "err", err.Error())
		return nil, fmt.Errorf(header+info+": %w", ErrUpdateUser)
	}

	u.log.Info(ctx, header+"User successfully updated")

	return user, nil
}

func (u *userUseCase) DeleteUser(ctx context.Context, id uuid.UUID) error {
	header := "DeleteUser: "

	u.log.Info(ctx, header+"Usecase called", "id", id)

	u.log.Info(ctx, header+"Making request to repo GetUserByID to check if user exits", "id", id)

	existingUser, err := u.repo.GetUserByID(ctx, id)

	if err != nil {
		info := "Failed to get user by id"
		u.log.Error(ctx, header+info, "err", err.Error())
		return fmt.Errorf(header+info+": %w", ErrGetUserByID)
	}

	if existingUser == nil {
		info := "User does not exist"
		u.log.Error(ctx, header+info)
		return errors.New(info)
	}

	u.log.Info(ctx, header+"User exists, making request to repo", "id", id)

	err = u.repo.DeleteUser(ctx, id)

	if err != nil {
		info := "Failed to delete user"
		u.log.Error(ctx, header+info, "err", err.Error())
		return fmt.Errorf(header+info+": %w", ErrDeleteUser)
	}

	u.log.Info(ctx, header+"User successfully deleted")

	return nil
}

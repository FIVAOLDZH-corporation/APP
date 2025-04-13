//go:build e2e

package e2e_test

import (
	lg "aggregator/internal/adapter/logger"
	httpAuth "aggregator/internal/adapter/service/auth/http"
	httpTodo "aggregator/internal/adapter/service/todo/http"
	httpUser "aggregator/internal/adapter/service/user/http"
	"aggregator/internal/common/logger"
	"aggregator/internal/config"
	"aggregator/internal/middleware"
	auth "aggregator/internal/service/auth"
	todo "aggregator/internal/service/todo"
	user "aggregator/internal/service/user"
	v1 "aggregator/internal/usecase/v1"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	v1api "aggregator/internal/api/v1"
	v2api "aggregator/internal/api/v2"
	v1handler "aggregator/internal/handler/v1"
	v2handler "aggregator/internal/handler/v2"

	"github.com/cucumber/godog"
	"github.com/gorilla/mux"
	"github.com/pquerna/otp/totp"
)

// AuthTestContext хранит состояние теста
type AuthTestContext struct {
	Server       *httptest.Server
	Client       *http.Client
	BaseURL      string
	CurrentUser  testUser
	LastResponse *http.Response
	Logger       logger.Logger
}

// testUser хранит данные пользователя
type testUser struct {
	Email      string
	Password   string
	TOTPSecret string
	TwoFA      bool
}

func SetupRouter() *mux.Router {
	logger := lg.NewEmptyLogger()

	var userSvc user.UserService
	{
		baseURL := "http://docker:8001/api/v1"
		// baseURL := "http://localhost:8001/api/v1"
		userSvc = httpUser.NewUserService(baseURL, 2*time.Second, logger)
	}

	var authSvc auth.AuthService
	{
		baseURL := "http://docker:8002/api/v2"
		// baseURL := "http://localhost:8002/api/v2"
		authSvc = httpAuth.NewAuthService(baseURL, 2*time.Second, logger)
	}

	var todoSvc todo.TodoService
	{
		baseURL := "http://docker:8003/api/v1"
		// baseURL := "http://localhost:8003/api/v1"
		todoSvc = httpTodo.NewTodoService(baseURL, 2*time.Second, logger)
	}

	uc := v1.NewAggregatorUseCase(userSvc, authSvc, todoSvc, logger)
	v1h := v1handler.NewAggregatorHandler(uc)
	v2h := v2handler.NewAggregatorHandler(uc)

	router := mux.NewRouter()
	loggingMiddleware := middleware.NewLoggingMiddleware(logger)
	router.Use(loggingMiddleware.Middleware)
	authMiddleware := middleware.NewAuthMiddleware(authSvc)
	v1api.InitializeV1Routes(router, v1h, authMiddleware)
	v2api.InitializeV2Routes(router, v1h, v2h, authMiddleware)

	return router
}

// Инициализация API-сервера перед тестами
func (ctx *AuthTestContext) StartServer() {
	router := SetupRouter() // Функция, которая поднимает API сервер
	ctx.Server = httptest.NewServer(router)
	ctx.Client = &http.Client{}
	ctx.BaseURL = ctx.Server.URL + "/api/v2"
	ctx.Logger = lg.NewZapLogger(config.LogConfig{Path: "log", Level: "debug"})
}

// Остановка сервера после тестов
func (ctx *AuthTestContext) StopServer() {
	ctx.Server.Close()
}

// Шаг 1: Создаём пользователя с 2FA или без
func (ctx *AuthTestContext) aUserWithPasswordAnd2FA(email, password, twoFA string) error {
	enable2FA := (twoFA == "enabled")
	secret := ""

	if enable2FA {
		secret = os.Getenv("CI_USER_SECRET") // "secretuser" // XXX:
	}

	ctx.CurrentUser = testUser{
		Email:      email,
		Password:   password,
		TOTPSecret: secret,
		TwoFA:      enable2FA,
	}

	return nil
}

// Шаг 2: Отправка запроса на API
func (ctx *AuthTestContext) theUserSendsRequest(endpoint, password string) error {
	payload := map[string]string{
		"email":    ctx.CurrentUser.Email,
		"password": password,
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", ctx.BaseURL+endpoint, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := ctx.Client.Do(req)
	if err != nil {
		return err
	}

	ctx.LastResponse = resp

	// respBody, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	return err
	// }
	// defer resp.Body.Close()

	// ctx.Logger.Info(context.TODO(), "theUserSendsRequest", "respBody", string(respBody), "baseurl", ctx.BaseURL+endpoint)
	return nil
}

// Шаг 3: Проверка, требует ли сервер 2FA
func (ctx *AuthTestContext) theUserIsPromptedForA2FA() error {
	defer ctx.LastResponse.Body.Close()
	var response map[string]interface{}
	json.NewDecoder(ctx.LastResponse.Body).Decode(&response)

	if ctx.LastResponse.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status 200 OK, got %d", ctx.LastResponse.StatusCode)
	}

	if response["2fa_required"] != true {
		return fmt.Errorf("expected 2fa_required to be true")
	}
	return nil
}

// Шаг 4: Отправка OTP-кода
func (ctx *AuthTestContext) theUserSubmitsAnOTP(endpoint, otp string) error {
	payload := map[string]string{
		"email": ctx.CurrentUser.Email,
		"otp":   otp,
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", ctx.BaseURL+endpoint, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := ctx.Client.Do(req)
	if err != nil {
		return err
	}

	ctx.LastResponse = resp
	return nil
}

func (ctx *AuthTestContext) theUserSubmitsPasswordsAndAnOTP(endpoint, oldPassword, newPassword, otp string) error {
	payload := map[string]string{
		"email":        ctx.CurrentUser.Email,
		"old_password": oldPassword,
		"new_password": newPassword,
		"otp":          otp,
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", ctx.BaseURL+endpoint, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := ctx.Client.Do(req)
	if err != nil {
		return err
	}

	ctx.LastResponse = resp
	return nil
}

// Шаг 5: Проверка успешного получения access_token
func (ctx *AuthTestContext) theUserReceivesAnAccessToken() error {
	defer ctx.LastResponse.Body.Close()
	var response map[string]interface{}
	json.NewDecoder(ctx.LastResponse.Body).Decode(&response)

	if ctx.LastResponse.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status 200 OK, got %d", ctx.LastResponse.StatusCode)
	}

	if _, ok := response["access_token"]; !ok {
		return fmt.Errorf("access_token not received")
	}
	return nil
}

// Шаг 6: Проверка, что ответ API соответствует JSON
func (ctx *AuthTestContext) theResponseShouldMatchJSON(expectedJSON string) error {
	defer ctx.LastResponse.Body.Close()

	body, _ := io.ReadAll(ctx.LastResponse.Body)
	var actualJSON map[string]interface{}
	var expected map[string]interface{}

	json.Unmarshal(body, &actualJSON)
	json.Unmarshal([]byte(expectedJSON), &expected)

	if !compareJSON(actualJSON, expected) {
		return fmt.Errorf("expected response %v, got %v", expected, actualJSON)
	}

	return nil
}

// Функция сравнения JSON-объектов
func compareJSON(actual, expected map[string]interface{}) bool {
	for k, v := range expected {
		if actual[k] != v {
			return false
		}
	}
	return true
}

// Шаг 7: Проверка отказа в аутентификации
func (ctx *AuthTestContext) theLoginAttemptIsRejected() error {
	defer ctx.LastResponse.Body.Close()
	if ctx.LastResponse.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("expected status 401 Unauthorized, got %d", ctx.LastResponse.StatusCode)
	}
	return nil
}

func (ctx *AuthTestContext) theUserReceivesNoError() error {
	defer ctx.LastResponse.Body.Close()
	if ctx.LastResponse.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status 200 OK, got %d", ctx.LastResponse.StatusCode)
	}
	return nil
}

func LoginFeatureContext(s *godog.ScenarioContext) {
	// Перед каждым сценарием запускаем сервер
	s.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		testCtx := &AuthTestContext{}
		testCtx.StartServer()
		return context.WithValue(ctx, "testCtx", testCtx), nil
	})

	// После каждого сценария останавливаем сервер
	s.After(func(ctx context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		testCtx, ok := ctx.Value("testCtx").(*AuthTestContext)
		if !ok {
			return ctx, fmt.Errorf("testCtx not found in context")
		}
		testCtx.StopServer()
		return ctx, nil
	})

	s.Step(`^a user "([^"]*)" with password "([^"]*)" and 2FA (enabled|disabled)$`, func(ctx context.Context, email, password, twoFA string) error {
		testCtx, ok := ctx.Value("testCtx").(*AuthTestContext)
		if !ok {
			return fmt.Errorf("testCtx not found in context")
		}
		return testCtx.aUserWithPasswordAnd2FA(email, password, twoFA)
	})

	s.Step(`^the user sends request to "([^"]*)" with password "([^"]*)"$`, func(ctx context.Context, endpoint, password string) error {
		testCtx, ok := ctx.Value("testCtx").(*AuthTestContext)
		if !ok {
			return fmt.Errorf("testCtx not found in context")
		}
		return testCtx.theUserSendsRequest(endpoint, password)
	})

	s.Step(`^the user is prompted for a 2FA code$`, func(ctx context.Context) error {
		testCtx, ok := ctx.Value("testCtx").(*AuthTestContext)
		if !ok {
			return fmt.Errorf("testCtx not found in context")
		}
		return testCtx.theUserIsPromptedForA2FA()
	})

	s.Step(`^the user sends request to "([^"]*)" with valid OTP$`, func(ctx context.Context, endpoint string) error {
		testCtx, ok := ctx.Value("testCtx").(*AuthTestContext)
		if !ok {
			return fmt.Errorf("testCtx not found in context")
		}
		otp, _ := totp.GenerateCode(testCtx.CurrentUser.TOTPSecret, time.Now())
		return testCtx.theUserSubmitsAnOTP(endpoint, otp)
	})

	s.Step(`^the user sends request to "([^"]*)" with OTP "([^"]*)"$`, func(ctx context.Context, endpoint, otp string) error {
		testCtx, ok := ctx.Value("testCtx").(*AuthTestContext)
		if !ok {
			return fmt.Errorf("testCtx not found in context")
		}
		return testCtx.theUserSubmitsAnOTP(endpoint, otp)
	})

	s.Step(`^the response on "([^"]*)" should match json:$`, func(ctx context.Context, expectedJSON *godog.DocString) error {
		testCtx, ok := ctx.Value("testCtx").(*AuthTestContext)
		if !ok {
			return fmt.Errorf("testCtx not found in context")
		}
		return testCtx.theResponseShouldMatchJSON(expectedJSON.Content)
	})

	s.Step(`^the user receives an access token$`, func(ctx context.Context) error {
		testCtx, ok := ctx.Value("testCtx").(*AuthTestContext)
		if !ok {
			return fmt.Errorf("testCtx not found in context")
		}
		return testCtx.theUserReceivesAnAccessToken()
	})

	s.Step(`^the login attempt is rejected$`, func(ctx context.Context) error {
		testCtx, ok := ctx.Value("testCtx").(*AuthTestContext)
		if !ok {
			return fmt.Errorf("testCtx not found in context")
		}
		return testCtx.theLoginAttemptIsRejected()
	})
}

func TestLogin(t *testing.T) {
	status := godog.TestSuite{
		Name:                "e2e-login",
		ScenarioInitializer: LoginFeatureContext,
		Options: &godog.Options{
			Format: "pretty",
			Paths:  []string{"features/login.feature"},
			Strict: true,
		},
	}.Run()

	if status > 0 {
		t.Fatal("non-zero status returned, failed to run login feature tests")
	}
}

func UpdatePasswordFeatureContext(s *godog.ScenarioContext) {
	s.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
		testCtx := &AuthTestContext{}
		testCtx.StartServer()
		return context.WithValue(ctx, "testCtx", testCtx), nil
	})

	s.After(func(ctx context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		testCtx, ok := ctx.Value("testCtx").(*AuthTestContext)
		if !ok {
			return ctx, fmt.Errorf("testCtx not found in context")
		}
		testCtx.StopServer()
		return ctx, nil
	})

	s.Step(`^a user "([^"]*)" with password "([^"]*)" and 2FA (enabled|disabled)$`, func(ctx context.Context, email, password, twoFA string) error {
		testCtx, ok := ctx.Value("testCtx").(*AuthTestContext)
		if !ok {
			return fmt.Errorf("testCtx not found in context")
		}
		return testCtx.aUserWithPasswordAnd2FA(email, password, twoFA)
	})

	s.Step(`^the user sends request to "([^"]*)" with passwords and valid OTP$`, func(ctx context.Context, endpoint string) error {
		testCtx, ok := ctx.Value("testCtx").(*AuthTestContext)
		if !ok {
			return fmt.Errorf("testCtx not found in context")
		}
		otp, _ := totp.GenerateCode(testCtx.CurrentUser.TOTPSecret, time.Now())
		oldPassword := "user"
		newPassword := "NeWP@SSw0rD"
		return testCtx.theUserSubmitsPasswordsAndAnOTP(endpoint, oldPassword, newPassword, otp)
	})

	s.Step(`^the user receives no error$`, func(ctx context.Context) error {
		testCtx, ok := ctx.Value("testCtx").(*AuthTestContext)
		if !ok {
			return fmt.Errorf("testCtx not found in context")
		}
		return testCtx.theUserReceivesNoError()
	})
}

func TestUpdatePassword(t *testing.T) {
	status := godog.TestSuite{
		Name:                "e2e-update-password",
		ScenarioInitializer: UpdatePasswordFeatureContext,
		Options: &godog.Options{
			Format: "pretty",
			Paths:  []string{"features/update_password.feature"},
			Strict: true,
		},
	}.Run()

	if status > 0 {
		t.Fatal("non-zero status returned, failed to run update password feature tests")
	}
}

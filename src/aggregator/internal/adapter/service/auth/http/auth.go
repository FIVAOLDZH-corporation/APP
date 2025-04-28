package http

import (
	"aggregator/internal/common/logger"
	"aggregator/internal/dto"
	"aggregator/internal/service/auth"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

var (
	ErrRegister          error             = errors.New("user wasn't created")
	ErrLogin             error             = errors.New("failed to log in")
	ErrRefresh           error             = errors.New("failed to refresh")
	ErrValidate          error             = errors.New("failed to validate token")
	ErrLogout            error             = errors.New("failed to log out")
	ErrLoginOTP          error             = errors.New("failed to log in with OTP")
	ErrGenerateOTPSecret error             = errors.New("failed to generate OTP secret")
	ErrEnable2FA         error             = errors.New("failed to enable 2FA")
	ErrDisable2FA        error             = errors.New("failed to disable 2FA")
	ErrValidateOTP       error             = errors.New("failed to validate OTP")
	ErrEnabled2FA        error             = errors.New("failed to check if 2FA is enabled")
	ErrUpdatePassword2FA error             = errors.New("failed to update password with 2FA")
	ErrVerifyEmail       error             = errors.New("failed to verify email")
	ErrDecodeResponse    func(error) error = func(err error) error {
		return fmt.Errorf("failed to decode response: %w", err)
	}
)

type AuthService struct {
	baseURL    string
	httpClient *http.Client
	log        logger.Logger
}

func NewAuthService(baseURL string, timeout time.Duration, logger logger.Logger) auth.AuthService {
	return &AuthService{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		log: logger,
	}
}

func (s *AuthService) Register(ctx context.Context, username, email, password string) (*dto.Tokens, error) {
	url := fmt.Sprintf("%s/register", s.baseURL)

	data := dto.RegisterRequest{
		Username: username,
		Email:    email,
		Password: password,
	}

	s.log.Info(ctx, "Making register request", "url", url, "data", data)

	method := http.MethodPost
	resp, err := s.makeRequest(ctx, method, url, data)
	if err != nil {
		s.log.Error(ctx, "Error making the request", "method", method, "url", url, "data", data)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		err = ErrRegister
		s.log.Error(ctx, err.Error())
		return nil, err
	}

	var tokens dto.Tokens
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		err = ErrDecodeResponse(err)
		s.log.Error(ctx, err.Error())
		return nil, err
	}

	return &tokens, nil
}

func (s *AuthService) Login(ctx context.Context, email, password string) (*dto.Tokens, error) {
	url := fmt.Sprintf("%s/login", s.baseURL)

	data := dto.LoginRequest{
		Email:    email,
		Password: password,
	}

	s.log.Info(ctx, "Making login request", "url", url, "data", data)

	method := http.MethodPost
	resp, err := s.makeRequest(ctx, method, url, data)
	if err != nil {
		s.log.Error(ctx, "Error making the request", "method", method, "url", url, "data", data)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = ErrLogin
		s.log.Error(ctx, err.Error())
		return nil, err
	}

	var tokens dto.Tokens
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		err = ErrDecodeResponse(err)
		s.log.Error(ctx, err.Error())
		return nil, err
	}

	return &tokens, nil
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (*dto.RefreshResponse, error) {
	url := fmt.Sprintf("%s/refresh", s.baseURL)

	data := dto.RefreshRequest{
		RefreshToken: refreshToken,
	}

	s.log.Info(ctx, "Making refresh request", "url", url, "data", data)

	method := http.MethodPost
	resp, err := s.makeRequest(ctx, method, url, data)
	if err != nil {
		s.log.Error(ctx, "Error making the request", "method", method, "url", url, "data", data)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = ErrRefresh
		s.log.Error(ctx, err.Error())
		return nil, err
	}

	var token dto.RefreshResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		err = ErrDecodeResponse(err)
		s.log.Error(ctx, err.Error())
		return nil, err
	}

	return &token, nil
}

func (s *AuthService) ValidateToken(ctx context.Context, token string) (*dto.ValidateTokenResponse, error) {
	url := fmt.Sprintf("%s/validate", s.baseURL)

	data := dto.ValidateTokenRequest{
		Token: token,
	}

	s.log.Info(ctx, "Making validate request", "url", url, "data", data)

	method := http.MethodPost
	resp, err := s.makeRequest(ctx, method, url, data)
	if err != nil {
		s.log.Error(ctx, "Error making the request", "method", method, "url", url, "data", data)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = ErrValidate
		s.log.Error(ctx, err.Error())
		return nil, err
	}

	var userData dto.ValidateTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
		err = ErrDecodeResponse(err)
		s.log.Error(ctx, err.Error())
		return nil, err
	}

	return &userData, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	url := fmt.Sprintf("%s/logout", s.baseURL)

	data := dto.LogoutRequest{
		RefreshToken: refreshToken,
	}

	s.log.Info(ctx, "Making logout request", "url", url, "data", data)

	method := http.MethodPost
	resp, err := s.makeRequest(ctx, method, url, data)
	if err != nil {
		s.log.Error(ctx, "Error making the request", "method", method, "url", url, "data", data)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = ErrLogout
		s.log.Error(ctx, err.Error())
		return err
	}

	return nil
}

func (s *AuthService) LoginOTP(ctx context.Context, email, otp string) (*dto.Tokens, error) {
	url := fmt.Sprintf("%s/2fa/login", s.baseURL)

	data := dto.LoginOTPRequest{
		Email: email,
		OTP:   otp,
	}

	s.log.Info(ctx, "Making login OTP request", "url", url, "data", data)

	method := http.MethodPost
	resp, err := s.makeRequest(ctx, method, url, data)
	if err != nil {
		s.log.Error(ctx, "Error making the request", "method", method, "url", url, "data", data)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = ErrLoginOTP
		s.log.Error(ctx, err.Error())
		return nil, err
	}

	var tokens dto.Tokens
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		err = ErrDecodeResponse(err)
		s.log.Error(ctx, err.Error())
		return nil, err
	}

	return &tokens, nil
}

func (s *AuthService) GenerateOTPSecret(ctx context.Context, email string) (string, error) {
	url := fmt.Sprintf("%s/2fa/init", s.baseURL)

	data := dto.GenerateOTPSecretRequest{
		Email: email,
	}

	s.log.Info(ctx, "Making GenerateOTPSecret request", "url", url, "data", data)

	method := http.MethodPost
	resp, err := s.makeRequest(ctx, method, url, data)
	if err != nil {
		s.log.Error(ctx, "Error making the request", "method", method, "url", url, "data", data)
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = ErrGenerateOTPSecret
		s.log.Error(ctx, err.Error())
		return "", err
	}

	var key dto.Key
	if err := json.NewDecoder(resp.Body).Decode(&key); err != nil {
		err = ErrDecodeResponse(err)
		s.log.Error(ctx, err.Error())
		return "", err
	}

	secret := key.Secret

	return secret, nil
}

func (s *AuthService) Enable2FA(ctx context.Context, email string) error {
	url := fmt.Sprintf("%s/2fa/enable", s.baseURL)

	data := dto.Enable2FARequest{
		Email: email,
	}

	s.log.Info(ctx, "Making Enable2FA request", "url", url, "data", data)

	method := http.MethodPost
	resp, err := s.makeRequest(ctx, method, url, data)
	if err != nil {
		s.log.Error(ctx, "Error making the request", "method", method, "url", url, "data", data)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = ErrEnable2FA
		s.log.Error(ctx, err.Error())
		return err
	}

	return nil
}

func (s *AuthService) Disable2FA(ctx context.Context, email string) error {
	url := fmt.Sprintf("%s/2fa/disable", s.baseURL)

	data := dto.Disable2FARequest{
		Email: email,
	}

	s.log.Info(ctx, "Making Disable2FA request", "url", url, "data", data)

	method := http.MethodPost
	resp, err := s.makeRequest(ctx, method, url, data)
	if err != nil {
		s.log.Error(ctx, "Error making the request", "method", method, "url", url, "data", data)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = ErrDisable2FA
		s.log.Error(ctx, err.Error())
		return err
	}

	return nil
}

func (s *AuthService) ValidateOTP(ctx context.Context, email, otp string) (bool, error) {
	url := fmt.Sprintf("%s/2fa/validate", s.baseURL)

	data := dto.ValidateOTPRequest{
		Email: email,
		OTP:   otp,
	}

	s.log.Info(ctx, "Making ValidateOTP request", "url", url, "data", data)

	method := http.MethodPost
	resp, err := s.makeRequest(ctx, method, url, data)
	if err != nil {
		s.log.Error(ctx, "Error making the request", "method", method, "url", url, "data", data)
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = ErrValidateOTP
		s.log.Error(ctx, err.Error())
		return false, err
	}

	var status dto.ValidStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		err = ErrDecodeResponse(err)
		s.log.Error(ctx, err.Error())
		return false, err
	}

	isValid := status.Valid

	return isValid, nil
}

func (s *AuthService) Enabled2FA(ctx context.Context, email string) (bool, error) {
	url := fmt.Sprintf("%s/2fa/enabled", s.baseURL)

	data := dto.Enabled2FARequest{
		Email: email,
	}

	s.log.Info(ctx, "Making Enabled2FA request", "url", url, "data", data)

	method := http.MethodPost
	resp, err := s.makeRequest(ctx, method, url, data)
	if err != nil {
		s.log.Error(ctx, "Error making the request", "method", method, "url", url, "data", data)
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = ErrEnabled2FA
		s.log.Error(ctx, err.Error())
		return false, err
	}

	var status dto.EnabledStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		err = ErrDecodeResponse(err)
		s.log.Error(ctx, err.Error())
		return false, err
	}

	enabled := status.Enabled

	return enabled, nil
}

func (s *AuthService) UpdatePassword2FA(ctx context.Context, email, oldPassword, newPassword, otp string) error {
	url := fmt.Sprintf("%s/2fa/update_password", s.baseURL)

	data := dto.UpdatePassword2FARequest{
		Email:       email,
		OldPassword: oldPassword,
		NewPassword: newPassword,
		OTP:         otp,
	}

	s.log.Info(ctx, "Making UpdatePassword2FA request", "url", url, "data", data)

	method := http.MethodPost
	resp, err := s.makeRequest(ctx, method, url, data)
	if err != nil {
		s.log.Error(ctx, "Error making the request", "method", method, "url", url, "data", data)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = ErrUpdatePassword2FA
		s.log.Error(ctx, err.Error())
		return err
	}

	return nil
}

func (s *AuthService) makeRequest(ctx context.Context, method, url string, data any) (*http.Response, error) {
	jsonBody, err := json.Marshal(data)
	if err != nil {
		err = fmt.Errorf("error marshaling user data: %w", err)
		s.log.Error(ctx, err.Error())
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(jsonBody))
	if err != nil {
		err = fmt.Errorf("error creating request: %w", err)
		s.log.Error(ctx, err.Error())
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		err = fmt.Errorf("error sending request: %w", err)
		s.log.Error(ctx, err.Error())
		return nil, err
	}

	return resp, nil
}

func (s *AuthService) VerifyEmail(ctx context.Context, email, code string) error {
	url := fmt.Sprintf("%s/verify-email", s.baseURL)

	data := dto.VerifyEmailRequest{
		Email: email,
		Code:  code,
	}

	s.log.Info(ctx, "Making VerifyEmail request", "url", url, "data", data)

	method := http.MethodPost
	resp, err := s.makeRequest(ctx, method, url, data)
	if err != nil {
		s.log.Error(ctx, "Error making the request", "method", method, "url", url, "data", data)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = ErrVerifyEmail
		s.log.Error(ctx, err.Error())
		return err
	}

	return nil
}

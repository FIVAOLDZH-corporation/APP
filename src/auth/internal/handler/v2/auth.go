package handler

import (
	"auth/internal/dto"
	"auth/internal/usecase"
	"encoding/json"
	"net/http"
)

type AuthHandler struct {
	authUsecase usecase.AuthUsecase
}

func NewAuthHandler(authUsecase usecase.AuthUsecase) *AuthHandler {
	return &AuthHandler{
		authUsecase: authUsecase,
	}
}

func (h *AuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	enabled2FA, _ := h.authUsecase.Enabled2FA(r.Context(), req.Email)

	if enabled2FA {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]bool{
			"2fa_required": true,
		})
		return
	}

	tokens, err := h.authUsecase.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(tokens)
}

func (h *AuthHandler) ValidateOTPHandler(w http.ResponseWriter, r *http.Request) {
	var req dto.ValidateOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	isValid, err := h.authUsecase.ValidateOTP(r.Context(), req.Email, req.OTP)
	if err != nil {
		http.Error(w, "Error while validating OTP", http.StatusInternalServerError)
		return
	}

	status := dto.ValidStatus{Valid: isValid}

	json.NewEncoder(w).Encode(status)
}

func (h *AuthHandler) LoginOTPHandler(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	tokens, err := h.authUsecase.LoginOTP(r.Context(), req.Email, req.OTP)
	if err != nil {
		http.Error(w, "Invalid email or OTP", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(tokens)
}

func (h *AuthHandler) GenerateOTPSecretHandler(w http.ResponseWriter, r *http.Request) {
	var req dto.GenerateOTPSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	secret, err := h.authUsecase.GenerateOTPSecret(r.Context(), req.Email)
	if err != nil {
		http.Error(w, "Couldn't generate secret", http.StatusInternalServerError)
		return
	}

	key := dto.Key{Secret: secret}

	json.NewEncoder(w).Encode(key)
}

func (h *AuthHandler) Enable2FAHandler(w http.ResponseWriter, r *http.Request) {
	var req dto.Enable2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err := h.authUsecase.Enable2FA(r.Context(), req.Email)
	if err != nil {
		http.Error(w, "Couldn't enable 2FA", http.StatusInternalServerError)
		return
	}
}

func (h *AuthHandler) Disable2FAHandler(w http.ResponseWriter, r *http.Request) {
	var req dto.Disable2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err := h.authUsecase.Disable2FA(r.Context(), req.Email)
	if err != nil {
		http.Error(w, "Couldn't disable 2FA", http.StatusInternalServerError)
		return
	}
}

func (h *AuthHandler) Enabled2FAHandler(w http.ResponseWriter, r *http.Request) {
	var req dto.Enabled2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	enabled, err := h.authUsecase.Enabled2FA(r.Context(), req.Email)
	if err != nil {
		http.Error(w, "Couldn't check if 2FA is enabled", http.StatusInternalServerError)
		return
	}

	status := dto.EnabledStatus{Enabled: enabled}

	json.NewEncoder(w).Encode(status)
}

func (h *AuthHandler) UpdatePassword2FAHandler(w http.ResponseWriter, r *http.Request) {
	var req dto.UpdatePassword2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err := h.authUsecase.UpdatePassword2FA(r.Context(), req.Email, req.OldPassword, req.NewPassword, req.OTP)
	if err != nil {
		http.Error(w, "Couldn't update password", http.StatusInternalServerError)
		return
	}
}

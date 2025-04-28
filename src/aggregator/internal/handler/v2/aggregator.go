package v2

import (
	"aggregator/internal/dto"
	"aggregator/internal/usecase"
	"encoding/json"
	"errors"
	"net/http"
)

var (
	ErrInvalidRequestBody error = errors.New("invalid request body")
)

type AggregatorHandler struct {
	uc usecase.AggregatorUseCase
}

func NewAggregatorHandler(uc usecase.AggregatorUseCase) *AggregatorHandler {
	return &AggregatorHandler{
		uc: uc,
	}
}

func (h *AggregatorHandler) LoginOTP(w http.ResponseWriter, r *http.Request) {
	var req dto.LoginOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, ErrInvalidRequestBody.Error(), http.StatusBadRequest)
		return
	}

	tokens, err := h.uc.LoginOTP(r.Context(), req.Email, req.OTP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(tokens)
}

func (h *AggregatorHandler) GenerateOTPSecret(w http.ResponseWriter, r *http.Request) {
	var req dto.GenerateOTPSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, ErrInvalidRequestBody.Error(), http.StatusBadRequest)
		return
	}

	secret, err := h.uc.GenerateOTPSecret(r.Context(), req.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	key := dto.Key{Secret: secret}

	json.NewEncoder(w).Encode(key)
}

func (h *AggregatorHandler) Enable2FA(w http.ResponseWriter, r *http.Request) {
	var req dto.Enable2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, ErrInvalidRequestBody.Error(), http.StatusBadRequest)
		return
	}

	err := h.uc.Enable2FA(r.Context(), req.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *AggregatorHandler) Disable2FA(w http.ResponseWriter, r *http.Request) {
	var req dto.Disable2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, ErrInvalidRequestBody.Error(), http.StatusBadRequest)
		return
	}

	err := h.uc.Disable2FA(r.Context(), req.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *AggregatorHandler) ValidateOTP(w http.ResponseWriter, r *http.Request) {
	var req dto.ValidateOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, ErrInvalidRequestBody.Error(), http.StatusBadRequest)
		return
	}

	isValid, err := h.uc.ValidateOTP(r.Context(), req.Email, req.OTP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	status := dto.ValidStatus{Valid: isValid}

	json.NewEncoder(w).Encode(status)
}

func (h *AggregatorHandler) Enabled2FA(w http.ResponseWriter, r *http.Request) {
	var req dto.Enabled2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, ErrInvalidRequestBody.Error(), http.StatusBadRequest)
		return
	}

	enabled, err := h.uc.Enabled2FA(r.Context(), req.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	status := dto.EnabledStatus{Enabled: enabled}

	json.NewEncoder(w).Encode(status)
}

func (h *AggregatorHandler) UpdatePassword2FA(w http.ResponseWriter, r *http.Request) {
	var req dto.UpdatePassword2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, ErrInvalidRequestBody.Error(), http.StatusBadRequest)
		return
	}

	err := h.uc.UpdatePassword2FA(r.Context(), req.Email, req.OldPassword, req.NewPassword, req.OTP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *AggregatorHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req dto.VerifyEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, ErrInvalidRequestBody.Error(), http.StatusBadRequest)
		return
	}

	err := h.uc.VerifyEmail(r.Context(), req.Email, req.Code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

package v2

import (
	v1 "auth/internal/handler/v1"
	v2 "auth/internal/handler/v2"

	"github.com/gorilla/mux"
)

func InitializeV2Routes(router *mux.Router, v1h *v1.AuthHandler, v2h *v2.AuthHandler) {
	router.HandleFunc("/api/v2/register", v1h.RegisterHandler).Methods("POST")
	router.HandleFunc("/api/v2/refresh", v1h.RefreshTokenHandler).Methods("POST")
	router.HandleFunc("/api/v2/validate", v1h.ValidateTokenHandler).Methods("POST")
	router.HandleFunc("/api/v2/logout", v1h.LogoutHandler).Methods("POST")
	router.HandleFunc("/api/v2/verify-email", v1h.VerifyEmailHandler).Methods("POST")

	router.HandleFunc("/api/v2/login", v2h.LoginHandler).Methods("POST")
	router.HandleFunc("/api/v2/2fa/validate", v2h.ValidateOTPHandler).Methods("POST")
	router.HandleFunc("/api/v2/2fa/login", v2h.LoginOTPHandler).Methods("POST")
	router.HandleFunc("/api/v2/2fa/init", v2h.GenerateOTPSecretHandler).Methods("POST")
	router.HandleFunc("/api/v2/2fa/enable", v2h.Enable2FAHandler).Methods("POST")
	router.HandleFunc("/api/v2/2fa/disable", v2h.Disable2FAHandler).Methods("POST")
	router.HandleFunc("/api/v2/2fa/enabled", v2h.Enabled2FAHandler).Methods("POST")                // XXX: GET better
	router.HandleFunc("/api/v2/2fa/update_password", v2h.UpdatePassword2FAHandler).Methods("POST") // XXX: PUT better
}

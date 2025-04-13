package v2

import (
	v1 "aggregator/internal/handler/v1"
	v2 "aggregator/internal/handler/v2"
	"aggregator/internal/middleware"

	"github.com/gorilla/mux"
)

func InitializeV2Routes(router *mux.Router, v1h *v1.AggregatorHandler, v2h *v2.AggregatorHandler, authMiddleware *middleware.AuthMiddleware) {
	router.HandleFunc("/api/v2/register", v1h.Register).Methods("POST")
	router.HandleFunc("/api/v2/login", v1h.Login).Methods("POST")
	router.HandleFunc("/api/v2/refresh", v1h.Refresh).Methods("POST")
	router.HandleFunc("/api/v2/validate", v1h.Validate).Methods("POST")
	router.HandleFunc("/api/v2/logout", v1h.Logout).Methods("POST")

	routes2FA := router.PathPrefix("/api/v2/2fa").Subrouter()
	routes2FA.HandleFunc("/validate", v2h.ValidateOTP).Methods("POST")
	routes2FA.HandleFunc("/login", v2h.LoginOTP).Methods("POST")
	routes2FA.HandleFunc("/init", v2h.GenerateOTPSecret).Methods("POST")
	routes2FA.HandleFunc("/enable", v2h.Enable2FA).Methods("POST")
	routes2FA.HandleFunc("/disable", v2h.Disable2FA).Methods("POST")
	routes2FA.HandleFunc("/enabled", v2h.Enabled2FA).Methods("POST")                // XXX: GET better
	routes2FA.HandleFunc("/update_password", v2h.UpdatePassword2FA).Methods("POST") // XXX: PUT better

	authRoutes := router.PathPrefix("/api/v2").Subrouter()
	authRoutes.Use(authMiddleware.Middleware)

	authRoutes.HandleFunc("/boards", v1h.GetBoards).Methods("GET")      // Boards
	authRoutes.HandleFunc("/board/{id}", v1h.GetBoard).Methods("GET")   // Columns + cards
	authRoutes.HandleFunc("/column/{id}", v1h.GetColumn).Methods("GET") // Cards
	authRoutes.HandleFunc("/card/{id}", v1h.GetCard).Methods("GET")     // Card + description

	authRoutes.HandleFunc("/board", v1h.CreateBoard).Methods("POST")
	authRoutes.HandleFunc("/column", v1h.CreateColumn).Methods("POST")
	authRoutes.HandleFunc("/card", v1h.CreateCard).Methods("POST")

	authRoutes.HandleFunc("/board", v1h.UpdateBoard).Methods("PUT")
	authRoutes.HandleFunc("/column", v1h.UpdateColumn).Methods("PUT")
	authRoutes.HandleFunc("/card", v1h.UpdateCard).Methods("PUT")

	authRoutes.HandleFunc("/board/{id}", v1h.DeleteBoard).Methods("DELETE")
	authRoutes.HandleFunc("/column/{id}", v1h.DeleteColumn).Methods("DELETE")
	authRoutes.HandleFunc("/card/{id}", v1h.DeleteCard).Methods("DELETE")

	authRoutes.HandleFunc("/stats/{from}/{to}", v1h.GetStats).Methods("GET")
	authRoutes.HandleFunc("/stats/{from}", v1h.GetStats).Methods("GET")
	authRoutes.HandleFunc("/stats", v1h.GetStats).Methods("GET")
}

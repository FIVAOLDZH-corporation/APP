package middleware

import (
	"aggregator/internal/common/logger"

	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type RateLimiterMiddleware struct {
	logger  logger.Logger
	clients map[string]*client
	mu      sync.Mutex
	rate    rate.Limit
	burst   int
}

type client struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func NewRateLimiterMiddleware(logger logger.Logger, r rate.Limit, b int) *RateLimiterMiddleware {
	rl := &RateLimiterMiddleware{
		logger:  logger,
		clients: make(map[string]*client),
		rate:    r,
		burst:   b,
	}
	go rl.cleanupExpiredClients()
	return rl
}

func (rl *RateLimiterMiddleware) getClient(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	c, exists := rl.clients[ip]
	if !exists {
		limiter := rate.NewLimiter(rl.rate, rl.burst)
		rl.clients[ip] = &client{limiter: limiter, lastSeen: time.Now()}
		return limiter
	}

	c.lastSeen = time.Now()
	return c.limiter
}

func (rl *RateLimiterMiddleware) cleanupExpiredClients() {
	for {
		time.Sleep(time.Minute)
		rl.mu.Lock()
		for ip, c := range rl.clients {
			if time.Since(c.lastSeen) > 3*time.Minute {
				delete(rl.clients, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *RateLimiterMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			rl.logger.Error(r.Context(), "failed to parse IP address: "+err.Error())
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		limiter := rl.getClient(ip)
		if !limiter.Allow() {
			rl.logger.Warn(r.Context(), "rate limit exceeded for IP: "+ip)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

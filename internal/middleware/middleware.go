// internal/middleware/middleware.go - HTTP middleware components
// This package demonstrates Go's approach to HTTP middleware
// It shows how to implement cross-cutting concerns like logging, CORS,
// request ID generation, panic recovery, and rate limiting

package middleware

import (
	// Standard library imports
	"context"         // Context for request lifecycle management
	"fmt"             // Formatted I/O
	"log"             // Logging
	"math/rand"       // Random number generation
	"net/http"        // HTTP server and client
	"runtime/debug"   // Stack trace generation
	"strings"         // String manipulation
	"sync"            // Synchronization primitives
	"time"            // Time handling
)

/*
REQUEST ID MIDDLEWARE
Generates and attaches unique request IDs to incoming requests
This helps with request tracking and debugging
*/

// RequestIDMiddleware adds a unique request ID to each request
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generate unique request ID
		requestID := generateRequestID()
		
		// Add request ID to response headers
		w.Header().Set("X-Request-ID", requestID)
		
		// Create new request with request ID in context
		ctx := r.Context()
		ctx = context.WithValue(ctx, "request_id", requestID)
		r = r.WithContext(ctx)
		
		// Log request start
		log.Printf("[RequestID] Started request %s: %s %s", requestID, r.Method, r.URL.Path)
		
		// Call next handler
		startTime := time.Now()
		next.ServeHTTP(w, r)
		
		// Log request completion
		duration := time.Since(startTime)
		log.Printf("[RequestID] Completed request %s in %v", requestID, duration)
	})
}

// generateRequestID creates a unique request identifier
func generateRequestID() string {
	// Use timestamp and random number for uniqueness
	timestamp := time.Now().UnixNano()
	random := rand.Int63()
	return fmt.Sprintf("req_%d_%d", timestamp, random)
}

/*
LOGGING MIDDLEWARE
Logs request details for monitoring and debugging
*/

// LoggingMiddleware logs HTTP request details
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get request ID from context if available
		requestID := getRequestIDFromContext(r)
		
		// Log request details
		log.Printf("[Logging] %s %s %s RemoteAddr: %s User-Agent: %s RequestID: %s",
			r.Method,
			r.URL.Path,
			r.Proto,
			r.RemoteAddr,
			r.UserAgent(),
			requestID,
		)
		
		// Log request headers in debug mode
		if r.Header.Get("X-Debug") == "true" {
			log.Printf("[Logging] Request headers for %s: %v", requestID, r.Header)
		}
		
		// Create response writer wrapper to capture status code
		wrapper := &responseWriterWrapper{
			ResponseWriter: w,
			statusCode:     http.StatusOK, // Default status
		}
		
		// Call next handler
		startTime := time.Now()
		next.ServeHTTP(wrapper, r)
		
		// Log response details
		duration := time.Since(startTime)
		log.Printf("[Logging] Response %s: Status=%d Duration=%v Size=%d",
			requestID,
			wrapper.statusCode,
			duration,
			wrapper.bytesWritten,
		)
		
		// Log slow requests
		if duration > 1*time.Second {
			log.Printf("[Logging] WARNING: Slow request detected: %s took %v", requestID, duration)
		}
	})
}

// responseWriterWrapper wraps http.ResponseWriter to capture status code and response size
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

// WriteHeader captures the status code
func (w *responseWriterWrapper) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// Write captures the number of bytes written
func (w *responseWriterWrapper) Write(data []byte) (int, error) {
	size, err := w.ResponseWriter.Write(data)
	w.bytesWritten += size
	return size, err
}

/*
CORS MIDDLEWARE
Handles Cross-Origin Resource Sharing headers
*/

// CORSMiddleware adds CORS headers to responses
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*") // Allow all origins (configurable)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
		w.Header().Set("Access-Control-Max-Age", "3600") // 1 hour cache
		
		// Handle preflight OPTIONS request
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		// Call next handler
		next.ServeHTTP(w, r)
	})
}

/*
RECOVERY MIDDLEWARE
Recovers from panics and prevents server crashes
*/

// RecoveryMiddleware recovers from panics in handlers
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Get request ID for logging
				requestID := getRequestIDFromContext(r)
				
				// Log the panic with stack trace
				log.Printf("[Recovery] PANIC recovered for request %s: %v", requestID, err)
				log.Printf("[Recovery] Stack trace for %s:\n%s", requestID, debug.Stack())
				
				// Send error response
				http.Error(w, 
					fmt.Sprintf("Internal server error (Request ID: %s)", requestID),
					http.StatusInternalServerError,
				)
			}
		}()
		
		// Call next handler
		next.ServeHTTP(w, r)
	})
}

/*
RATE LIMITING MIDDLEWARE
Implements basic rate limiting to prevent abuse
*/

// RateLimiter struct holds rate limiting state
type RateLimiter struct {
	requests map[string][]time.Time // IP address to request timestamps mapping
	mu       sync.RWMutex           // Mutex for concurrent access
	limit    int                    // Maximum requests per window
	window   time.Duration          // Time window for rate limiting
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(requestsPerSecond int, windowSeconds int) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    requestsPerSecond * windowSeconds, // Total requests allowed in window
		window:   time.Duration(windowSeconds) * time.Second,
	}
}

// RateLimitMiddleware creates a rate limiting middleware
func RateLimitMiddleware(rateLimiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get client IP address
			clientIP := getClientIP(r)
			
			// Check rate limit
			if !rateLimiter.allowRequest(clientIP) {
				requestID := getRequestIDFromContext(r)
				log.Printf("[RateLimit] Rate limit exceeded for IP %s (Request ID: %s)", clientIP, requestID)
				
				// Send rate limit exceeded response
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", rateLimiter.limit))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				
				fmt.Fprintf(w, `{"error": "Rate limit exceeded", "code": "RATE_LIMIT_EXCEEDED"}`)
				return
			}
			
			// Call next handler
			next.ServeHTTP(w, r)
		})
	}
}

// allowRequest checks if a request from the given IP is allowed
func (rl *RateLimiter) allowRequest(clientIP string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	
	// Get request history for this IP
	history, exists := rl.requests[clientIP]
	if !exists {
		// First request from this IP
		rl.requests[clientIP] = []time.Time{now}
		return true
	}
	
	// Remove old requests outside the window
	cutoff := now.Add(-rl.window)
	validRequests := make([]time.Time, 0)
	for _, timestamp := range history {
		if timestamp.After(cutoff) {
			validRequests = append(validRequests, timestamp)
		}
	}
	
	// Check if limit exceeded
	if len(validRequests) >= rl.limit {
		rl.requests[clientIP] = validRequests // Update with filtered history
		return false
	}
	
	// Add current request
	validRequests = append(validRequests, now)
	rl.requests[clientIP] = validRequests
	
	return true
}

/*
AUTHENTICATION MIDDLEWARE
Basic authentication middleware (placeholder for demonstration)
*/

// AuthMiddleware provides basic authentication
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for public endpoints
		if isPublicEndpoint(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		
		// Get authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			sendAuthError(w, "Missing authorization header")
			return
		}
		
		// Validate authorization header format
		if !strings.HasPrefix(authHeader, "Bearer ") {
			sendAuthError(w, "Invalid authorization header format")
			return
		}
		
		// Extract token
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			sendAuthError(w, "Empty authorization token")
			return
		}
		
		// Validate token (placeholder - implement actual token validation)
		if !isValidToken(token) {
			sendAuthError(w, "Invalid authorization token")
			return
		}
		
		// Add user information to context (placeholder)
		ctx := r.Context()
		ctx = context.WithValue(ctx, "user_id", "user123")
		ctx = context.WithValue(ctx, "user_roles", []string{"user"})
		r = r.WithContext(ctx)
		
		// Call next handler
		next.ServeHTTP(w, r)
	})
}

// isPublicEndpoint checks if an endpoint doesn't require authentication
func isPublicEndpoint(path string) bool {
	publicEndpoints := []string{
		"/health",
		"/api/users",
		"/api/calculate",
		"/api/goroutines",
	}
	
	for _, endpoint := range publicEndpoints {
		if strings.HasPrefix(path, endpoint) {
			return true
		}
	}
	
	return false
}

// isValidToken validates an authentication token (placeholder implementation)
func isValidToken(token string) bool {
	// Placeholder token validation
	// In a real implementation, you would:
	// 1. Validate token format (JWT, etc.)
	// 2. Check token signature
	// 3. Check token expiration
	// 4. Look up token in database/cache
	
	validTokens := map[string]bool{
		"demo_token_123": true,
		"demo_token_456": true,
	}
	
	return validTokens[token]
}

// sendAuthError sends an authentication error response
func sendAuthError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", "Bearer")
	w.WriteHeader(http.StatusUnauthorized)
	
	fmt.Fprintf(w, `{"error": "%s", "code": "UNAUTHORIZED"}`, message)
}

/*
SECURITY MIDDLEWARE
Adds security-related headers and protections
*/

// SecurityMiddleware adds security headers to responses
func SecurityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		
		// Remove server header to hide server information
		w.Header().Del("Server")
		
		// Call next handler
		next.ServeHTTP(w, r)
	})
}

/*
UTILITY FUNCTIONS
Helper functions used by middleware
*/

// getRequestIDFromContext extracts request ID from request context
func getRequestIDFromContext(r *http.Request) string {
	if requestID := r.Context().Value("request_id"); requestID != nil {
		if id, ok := requestID.(string); ok {
			return id
		}
	}
	return "unknown"
}

// getClientIP extracts the real client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (common for proxies/load balancers)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	
	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}
	
	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if colonIndex := strings.LastIndex(ip, ":"); colonIndex != -1 {
		ip = ip[:colonIndex] // Remove port number
	}
	
	return ip
}

/*
CONTEXT KEY DEFINITIONS
Define custom types for context keys to prevent collisions
*/

// ContextKey is a custom type for context keys
type ContextKey string

// Context keys
const (
	RequestIDKey ContextKey = "request_id"
	UserIDKey    ContextKey = "user_id"
	UserRolesKey ContextKey = "user_roles"
	ConfigKey    ContextKey = "config"
)

/*
COMPOSITE MIDDLEWARE
Combine multiple middleware functions for easier usage
*/

// CommonMiddleware applies commonly used middleware in the correct order
func CommonMiddleware(next http.Handler) http.Handler {
	return RequestIDMiddleware(
		LoggingMiddleware(
			RecoveryMiddleware(
				CORSMiddleware(
					SecurityMiddleware(next),
				),
			),
		),
	)
}

// SecureMiddleware applies middleware for secure endpoints
func SecureMiddleware(rateLimiter *RateLimiter, next http.Handler) http.Handler {
	return RequestIDMiddleware(
		LoggingMiddleware(
			RecoveryMiddleware(
				AuthMiddleware(
					RateLimitMiddleware(rateLimiter)(
						SecurityMiddleware(next),
					),
				),
			),
		),
	)
}

/*
CONFIGURABLE MIDDLEWARE
Middleware that can be configured based on application needs
*/

// ConfigurableCORSMiddleware creates CORS middleware with custom configuration
func ConfigurableCORSMiddleware(allowedOrigins []string, allowedMethods []string, allowedHeaders []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Determine allowed origin
			origin := r.Header.Get("Origin")
			allowedOrigin := ""
			
			if len(allowedOrigins) == 0 || (len(allowedOrigins) == 1 && allowedOrigins[0] == "*") {
				allowedOrigin = origin // Allow all origins
			} else {
				// Check if origin is in allowed list
				for _, allowed := range allowedOrigins {
					if allowed == origin {
						allowedOrigin = origin
						break
					}
				}
			}
			
			// Set CORS headers
			if allowedOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			}
			
			if len(allowedMethods) > 0 {
				w.Header().Set("Access-Control-Allow-Methods", strings.Join(allowedMethods, ", "))
			} else {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			}
			
			if len(allowedHeaders) > 0 {
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(allowedHeaders, ", "))
			} else {
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
			}
			
			w.Header().Set("Access-Control-Max-Age", "3600")
			
			// Handle preflight OPTIONS request
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}
			
			// Call next handler
			next.ServeHTTP(w, r)
		})
	}
}
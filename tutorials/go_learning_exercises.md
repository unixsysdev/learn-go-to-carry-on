
# Go Learning Exercises: From Beginner to Advanced

## Table of Contents
1. [Introduction](#introduction)
2. [Beginner Exercises](#beginner-exercises)
   - [Exercise 1: Modify the User Model](#exercise-1-modify-the-user-model)
   - [Exercise 2: Add a New Endpoint](#exercise-2-add-a-new-endpoint)
   - [Exercise 3: Implement Authentication](#exercise-3-implement-authentication)
   - [Exercise 4: Add Database Support](#exercise-4-add-database-support)
3. [Intermediate Exercises](#intermediate-exercises)
   - [Exercise 5: Implement WebSockets](#exercise-5-implement-websockets)
   - [Exercise 6: Add Rate Limiting](#exercise-6-add-rate-limiting)
   - [Exercise 7: Create Unit Tests](#exercise-7-create-unit-tests)

## Introduction

This document provides a series of exercises designed to help you learn Go programming by extending the existing application. The exercises are organized into three difficulty levels:

- **Beginner**: Focus on basic modifications and additions to the existing codebase
- **Intermediate**: Introduce more complex concepts and external dependencies
- **Advanced**: Explore architectural patterns and deployment strategies

Each exercise includes:
- A clear objective
- Step-by-step instructions
- Code examples
- Testing guidance
- Explanations of key concepts

We assume you have little to no prior knowledge of Go or the codebase. Each exercise builds on the previous ones, so it's recommended to complete them in order.

## Beginner Exercises

### Exercise 1: Modify the User Model

#### Objective

Add a new field to the User struct and update the validation logic to ensure data integrity.

#### What You'll Learn

- How to modify data structures in Go
- How to update validation logic
- How to ensure changes are consistent across the application

#### Background

The User model is defined in [`internal/models/models.go`](internal/models/models.go:1). It currently includes fields like ID, Username, Email, etc. We'll add a "PhoneNumber" field to allow users to store their phone numbers.

#### Step 1: Update the User Struct

1. Open [`internal/models/models.go`](internal/models/models.go:1)
2. Find the User struct definition (around line 22)
3. Add a new field for phone number:

```go
type User struct {
    ID        int       `json:"id"`         // Unique identifier
    Username  string    `json:"username"`   // Unique username
    Email     string    `json:"email"`      // Email address
    FirstName string    `json:"first_name"` // First name
    LastName  string    `json:"last_name"`  // Last name
    Age       int       `json:"age"`        // Age in years
    Active    bool      `json:"active"`     // Account status
    CreatedAt time.Time `json:"created_at"` // Account creation timestamp
    UpdatedAt time.Time `json:"updated_at"` // Last update timestamp
    Roles     []string  `json:"roles"`      // User roles/permissions
    Profile   *Profile  `json:"profile,omitempty"` // Optional profile information
    ResetToken           string    `json:"-"`                 // Password reset token (hidden from JSON)
    ResetTokenExpiresAt  time.Time `json:"-"`                 // When the reset token expires (hidden from JSON)
    
    // ADD THIS NEW FIELD:
    PhoneNumber string `json:"phone_number"` // User's phone number
}
```

#### Step 2: Update the Validation Logic

1. Find the `Validate` method for the User struct (around line 164)
2. Add validation for the phone number:

```go
func (u *User) Validate() error {
    // Existing validation code...
    
    // Phone number validation
    if u.PhoneNumber != "" {
        // Remove all non-digit characters for validation
        digitsOnly := regexp.MustCompile(`[^\d]`).ReplaceAllString(u.PhoneNumber, "")
        
        // Check if it has a reasonable number of digits (between 10 and 15)
        if len(digitsOnly) < 10 || len(digitsOnly) > 15 {
            return fmt.Errorf("phone number must have between 10 and 15 digits")
        }
        
        // Check if it contains only digits and valid separators (+, -, space, parentheses)
        phoneRegex := regexp.MustCompile(`^[\d\+\-\s\(\)]+$`)
        if !phoneRegex.MatchString(u.PhoneNumber) {
            return fmt.Errorf("phone number can only contain digits, spaces, and the characters +, -, (, )")
        }
    }
    
    return nil
}
```

#### Step 3: Update the Factory Function

1. Find the `NewUser` factory function (around line 346)
2. Update it to include the phone number parameter:

```go
func NewUser(username, email, firstName, lastName, phoneNumber string) *User {
    return &User{
        Username:    username,
        Email:       email,
        FirstName:   firstName,
        LastName:    lastName,
        PhoneNumber: phoneNumber, // Add this line
        Active:      true,
        CreatedAt:   time.Now(),
        UpdatedAt:   time.Now(),
        Roles:       []string{"user"}, // Default role
    }
}
```

#### Step 4: Update the Sample Users

1. Find the `initializeSampleUsers` method in [`internal/services/services.go`](internal/services/services.go:90)
2. Update it to include phone numbers:

```go
func (s *UserService) initializeSampleUsers() {
    sampleUsers := []*models.User{
        models.NewUser("alice_dev", "alice@example.com", "Alice", "Johnson", "+1 (555) 123-4567"),
        models.NewUser("bob_coder", "bob@example.com", "Bob", "Smith", "+44 20 7946 0958"),
        models.NewUser("charlie_go", "charlie@example.com", "Charlie", "Brown", "+81 3-1234-5678"),
        models.NewUser("diana_admin", "diana@example.com", "Diana", "Wilson", "+61 2 9876 5432"),
        models.NewUser("eve_tester", "eve@example.com", "Eve", "Davis", "+49 30 12345678"),
    }
    
    // Rest of the method remains the same...
}
```

#### Step 5: Test Your Changes

1. Run the application:
```bash
go run cmd/server/main.go
```

2. Test the API by creating a new user with a phone number:
```bash
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "newuser@example.com",
    "first_name": "New",
    "last_name": "User",
    "age": 25,
    "phone_number": "+1 (555) 987-6543"
  }'
```

3. Test with invalid phone numbers:
```bash
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser2",
    "email": "newuser2@example.com",
    "first_name": "New",
    "last_name": "User2",
    "age": 25,
    "phone_number": "invalid-phone"
  }'
```

#### Key Concepts Explained

1. **Struct Tags**: The `` `json:"phone_number"` `` tag tells Go how to serialize this field to JSON. When the struct is converted to JSON, the field will be named "phone_number".

2. **Validation**: We added validation logic to ensure phone numbers have a reasonable format. This prevents bad data from entering our system.

3. **Factory Function**: The `NewUser` function is a "constructor" that creates new User instances with sensible defaults. We updated it to accept a phone number parameter.

4. **Regular Expressions**: We used regular expressions to validate the phone number format. The first regex removes all non-digit characters to count the digits, and the second regex checks that the phone number only contains valid characters.

#### Troubleshooting

- **Compilation Error**: If you get an error about `regexp` not being imported, add `"regexp"` to the import statement at the top of [`internal/models/models.go`](internal/models/models.go:8).
- **Validation Not Working**: Make sure you've added the validation logic to the `Validate` method, not just the `ValidateCreate` or `ValidateUpdate` methods.
- **Phone Number Not Saving**: Make sure you've updated the `NewUser` factory function and the sample users initialization.

### Exercise 2: Add a New Endpoint

#### Objective

Create a new API endpoint that returns user statistics, such as the total number of users and the number of active users.

#### What You'll Learn

- How to add new API endpoints
- How to structure API responses
- How to implement business logic for data aggregation

#### Background

Currently, the application has endpoints for CRUD operations on users, but it doesn't provide any statistics or analytics about the users. We'll add a new endpoint `/api/users/stats` that returns user statistics.

#### Step 1: Update the Models

1. Open [`internal/models/models.go`](internal/models/models.go:1)
2. Add a new struct for the statistics response at the end of the file (before the utility functions):

```go
/*
USER STATISTICS STRUCTS
Define structures for user statistics
*/

// UserStats represents user statistics
type UserStats struct {
    TotalUsers    int `json:"total_users"`     // Total number of users
    ActiveUsers   int `json:"active_users"`    // Number of active users
    InactiveUsers int `json:"inactive_users"`  // Number of inactive users
    AverageAge    int `json:"average_age"`     // Average age of users
}
```

#### Step 2: Update the Service Interface

1. Open [`internal/services/services.go`](internal/services/services.go:1)
2. Find the `UserServiceInterface` definition (around line 30)
3. Add a new method signature:

```go
type UserServiceInterface interface {
    GetUserByID(id int) (*models.User, error)
    GetAllUsers() ([]*models.User, error)
    CreateUser(user *models.User) error
    UpdateUser(user *models.User) error
    DeleteUser(id int) error
    GetUserByUsername(username string) (*models.User, error)
    SearchUsers(query string) ([]*models.User, error)
    RequestPasswordReset(email string) error
    ResetPassword(token, newPassword string) error
    ValidateResetToken(token string) (*User, error)
    
    // ADD THIS NEW METHOD SIGNATURE:
    GetUserStats() (*models.UserStats, error)
}
```

#### Step 3: Implement the Service Method

1. In the same file, find the UserService struct implementation
2. Add the implementation of the new method at the end of the UserService implementation:

```go
// GetUserStats calculates and returns user statistics
func (s *UserService) GetUserStats() (*models.UserStats, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    stats := &models.UserStats{
        TotalUsers:    len(s.users),
        ActiveUsers:   0,
        InactiveUsers: 0,
    }
    
    var totalAge int
    
    for _, user := range s.users {
        if user.Active {
            stats.ActiveUsers++
        } else {
            stats.InactiveUsers++
        }
        
        totalAge += user.Age
    }
    
    // Calculate average age (handle division by zero)
    if stats.TotalUsers > 0 {
        stats.AverageAge = totalAge / stats.TotalUsers
    }
    
    return stats, nil
}
```

#### Step 4: Update the Handler

1. Open [`internal/handlers/handlers.go`](internal/handlers/handlers.go:1)
2. Add a new handler method at the end of the APIHandler implementation:

```go
/*
USER STATISTICS HANDLERS
Handle user statistics requests
*/

// GetUserStatsHandler handles GET /api/users/stats
func (h *APIHandler) GetUserStatsHandler(w http.ResponseWriter, r *http.Request) {
    // Only allow GET method
    if r.Method != http.MethodGet {
        sendErrorResponse(w, "Method not allowed", "METHOD_NOT_ALLOWED", 
            http.StatusMethodNotAllowed, getRequestID(r))
        return
    }
    
    // Get user statistics
    stats, err := h.userService.GetUserStats()
    if err != nil {
        sendErrorResponse(w, fmt.Sprintf("Failed to get user statistics: %v", err), 
            "STATS_RETRIEVAL_ERROR", http.StatusInternalServerError, getRequestID(r))
        return
    }
    
    // Send success response
    response := models.SuccessResponse{
        Message:   "User statistics retrieved successfully",
        Data:      stats,
        Timestamp: time.Now().Unix(),
        RequestID: getRequestID(r),
    }
    
    sendJSONResponse(w, response, http.StatusOK)
}
```

#### Step 5: Update the Routes

1. Open [`cmd/server/main.go`](cmd/server/main.go:1)
2. Find the route registration section (around line 100)
3. Add the new route:

```go
mux := http.NewServeMux()

// Existing routes
mux.HandleFunc("/health", apiHandler.HealthCheck)
mux.HandleFunc("/api/users", apiHandler.UsersHandler)
mux.HandleFunc("/api/users/", apiHandler.UserHandler)
mux.HandleFunc("/api/calculate", apiHandler.CalculateHandler)
mux.HandleFunc("/api/goroutines", apiHandler.GoroutineHandler)
mux.HandleFunc("/ws", wsHandler.HandleWebSocket)
mux.HandleFunc("/api/users/request-password-reset", apiHandler.RequestPasswordResetHandler)
mux.HandleFunc("/api/users/reset-password", apiHandler.ResetPasswordHandler)

// ADD THIS NEW ROUTE:
mux.HandleFunc("/api/users/stats", apiHandler.GetUserStatsHandler)

// Static file serving
mux.Handle("/", staticHandler)
```

#### Step 6: Test Your Changes

1. Run the application:
```bash
go run cmd/server/main.go
```

2. Test the new endpoint:
```bash
curl -X GET http://localhost:8080/api/users/stats
```

You should see a response like:
```json
{
  "message": "User statistics retrieved successfully",
  "data": {
    "total_users": 5,
    "active_users": 5,
    "inactive_users": 0,
    "average_age": 30
  },
  "timestamp": 1634567890,
  "request_id": "req_1234567890"
}
```

#### Key Concepts Explained

1. **API Design**: We followed RESTful conventions by using GET method for retrieving data and a logical URL structure (`/api/users/stats`).

2. **Data Aggregation**: The service method aggregates data from multiple user records to calculate statistics. This is a common pattern in analytics and reporting features.

3. **Thread Safety**: We used a read lock (`RLock()` instead of `Lock()`) because we're only reading data, not modifying it. This allows multiple concurrent reads without blocking each other.

4. **Response Structure**: We used the existing `SuccessResponse` struct to maintain consistency with other endpoints in the API.

#### Troubleshooting

- **404 Not Found**: If you get a 404 error, make sure you've added the route in `cmd/server/main.go` and that the URL you're using matches exactly.
- **Compilation Error**: If you get an error about the `GetUserStats` method not being implemented, make sure you've added it to both the interface and the implementation.
- **Empty Statistics**: If the statistics are empty or zero, make sure the sample users are being initialized correctly in the `initializeSampleUsers` method.

### Exercise 3: Implement Authentication

#### Objective

Add JWT (JSON Web Token) based authentication to protect certain endpoints.

#### What You'll Learn

- How to implement token-based authentication
- How to create and validate JWTs
- How to protect endpoints with middleware
- How to manage user sessions

#### Background

Currently, the application doesn't have any authentication mechanism. Anyone can access any endpoint. We'll add JWT-based authentication to protect certain endpoints, requiring users to log in and provide a valid token to access protected resources.

#### Step 1: Add Dependencies

First, we need to add a JWT library to our project. We'll use the popular `github.com/golang-jwt/jwt` package.

1. Open your terminal and run:
```bash
go get github.com/golang-jwt/jwt/v5
```

#### Step 2: Update the Configuration

1. Open [`internal/config/config.go`](internal/config/config.go:1)
2. Add JWT configuration fields to the Config struct:

```go
type Config struct {
    // ... existing fields ...
    
    // JWT configuration
    JWTSecret     string        // Secret key for signing JWTs
    JWTExpiration time.Duration // JWT token expiration time
}
```

3. Update the `LoadConfig` function to include JWT configuration:

```go
func LoadConfig() (*Config, error) {
    config := &Config{
        // ... existing configuration ...
        
        // JWT configuration
        JWTSecret:     getEnvOrDefault("JWT_SECRET", "your-secret-key"),
        JWTExpiration: getEnvDurationOrDefault("JWT_EXPIRATION", 24*time.Hour),
    }
    
    // ... rest of the function ...
}
```

4. Add the helper function for duration parsing:

```go
// getEnvDurationOrDefault retrieves duration environment variable or returns default
func getEnvDurationOrDefault(key string, defaultValue time.Duration) time.Duration {
    if value := os.Getenv(key); value != "" {
        if duration, err := time.ParseDuration(value); err == nil {
            return duration
        }
    }
    return defaultValue
}
```

#### Step 3: Create Authentication Models

1. Open [`internal/models/models.go`](internal/models/models.go:1)
2. Add authentication-related models at the end of the file (before the utility functions):

```go
/*
AUTHENTICATION MODELS
Define structures for authentication
*/

// LoginRequest represents a login request
type LoginRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

// LoginResponse represents a login response
type LoginResponse struct {
    Token string `json:"token"`
    User  *User  `json:"user"`
}

// Validate implements Validator interface for LoginRequest
func (lr *LoginRequest) Validate() error {
    if strings.TrimSpace(lr.Username) == "" {
        return fmt.Errorf("username cannot be empty")
    }
    
    if strings.TrimSpace(lr.Password) == "" {
        return fmt.Errorf("password cannot be empty")
    }
    
    return nil
}
```

#### Step 4: Create Authentication Service

1. Create a new file [`internal/services/auth.go`](internal/services/auth.go:1) with the following content:

```go
package services

import (
    "fmt"
    "time"
    
    "github.com/golang-jwt/jwt/v5"
    "scholastic-go-tutorial/internal/models"
)

// AuthService handles authentication logic
type AuthService struct {
    userService UserServiceInterface
    jwtSecret   string
    jwtExpiration time.Duration
}

// NewAuthService creates a new AuthService instance
func NewAuthService(userService UserServiceInterface, jwtSecret string, jwtExpiration time.Duration) *AuthService {
    return &AuthService{
        userService:   userService,
        jwtSecret:     jwtSecret,
        jwtExpiration: jwtExpiration,
    }
}

// AuthServiceInterface defines the contract for authentication operations
type AuthServiceInterface interface {
    Login(username, password string) (string, *models.User, error)
    ValidateToken(tokenString string) (*jwt.Token, error)
}

// Login authenticates a user and returns a JWT token
func (s *AuthService) Login(username, password string) (string, *models.User, error) {
    // Find user by username
    user, err := s.userService.GetUserByUsername(username)
    if err != nil {
        return "", nil, fmt.Errorf("invalid credentials")
    }
    
    // In a real application, you would hash and compare passwords
    // For this example, we'll use a simple check
    if password != "password" {
        return "", nil, fmt.Errorf("invalid credentials")
    }
    
    // Check if user is active
    if !user.Active {
        return "", nil, fmt.Errorf("account is inactive")
    }
    
    // Create JWT token
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "user_id":  user.ID,
        "username": user.Username,
        "roles":    user.Roles,
        "exp":      time.Now().Add(s.jwtExpiration).Unix(),
    })
    
    // Sign the token with the secret key
    tokenString, err := token.SignedString([]byte(s.jwtSecret))
    if err != nil {
        return "", nil, fmt.Errorf("failed to generate token: %w", err)
    }
    
    return tokenString, user, nil
}

// ValidateToken validates a JWT token and returns the token
func (s *AuthService) ValidateToken(tokenString string) (*jwt.Token, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Validate the signing method
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        
        return []byte(s.jwtSecret), nil
    })
    
    if err != nil {
        return nil, err
    }
    
    return token, nil
}
```

#### Step 5: Create Authentication Middleware

1. Open [`internal/middleware/middleware.go`](internal/middleware/middleware.go:1)
2. Add the authentication middleware at the end of the file:

```go
/*
AUTHENTICATION MIDDLEWARE
Handles JWT token validation
*/

// AuthMiddleware creates a middleware that validates JWT tokens
func AuthMiddleware(authService services.AuthServiceInterface) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
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
            tokenString := strings.TrimPrefix(authHeader, "Bearer ")
            if tokenString == "" {
                sendAuthError(w, "Empty authorization token")
                return
            }
            
            // Validate token
            token, err := authService.ValidateToken(tokenString)
            if err != nil {
                sendAuthError(w, "Invalid or expired token")
                return
            }
            
            // Extract claims
            if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
                // Add user information to context
                ctx := r.Context()
                ctx = context.WithValue(ctx, "user_id", claims["user_id"])
                ctx = context.WithValue(ctx, "username", claims["username"])
                ctx = context.WithValue(ctx, "roles", claims["roles"])
                r = r.WithContext(ctx)
                
                // Call next handler
                next.ServeHTTP(w, r)
            } else {
                sendAuthError(w, "Invalid token claims")
                return
            }
        })
    }
}

// isPublicEndpoint checks if an endpoint doesn't require authentication
func isPublicEndpoint(path string) bool {
    publicEndpoints := []string{
        "/health",
        "/api/login",
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

// sendAuthError sends an authentication error response
func sendAuthError(w http.ResponseWriter, message string) {
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("WWW-Authenticate", "Bearer")
    w.WriteHeader(http.StatusUnauthorized)
    
    fmt.Fprintf(w, `{"error": "%s", "code": "UNAUTHORIZED"}`, message)
}
```

#### Step 6: Update the Handlers

1. Open [`internal/handlers/handlers.go`](internal/handlers/handlers.go:1)
2. Add the authentication handler at the end of the APIHandler implementation:

```go
/*
AUTHENTICATION HANDLERS
Handle authentication requests
*/

// LoginHandler handles POST /api/login
func (h *APIHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
    // Only allow POST method
    if r.Method != http.MethodPost {
        sendErrorResponse(w, "Method not allowed", "METHOD_NOT_ALLOWED", 
            http.StatusMethodNotAllowed, getRequestID(r))
        return
    }
    
    // Parse request body
    var request models.LoginRequest
    if err := parseJSONBody(r, &request); err != nil {
        sendErrorResponse(w, "Invalid request body", "INVALID_REQUEST_BODY", 
            http.StatusBadRequest, getRequestID(r))
        return
    }
    
    // Validate request
    if err := request.Validate(); err != nil {
        sendErrorResponse(w, fmt.Sprintf("Validation failed: %v", err), "VALIDATION_ERROR", 
            http.StatusBadRequest, getRequestID(r))
        return
    }
    
    // Authenticate user
    token, user, err := h.authService.Login(request.Username, request.Password)
    if err != nil {
        sendErrorResponse(w, fmt.Sprintf("Authentication failed: %v", err), 
            "AUTHENTICATION_FAILED", http.StatusUnauthorized, getRequestID(r))
        return
    }
    
    // Send success response
    response := models.SuccessResponse{
        Message: "Login successful",
        Data: models.LoginResponse{
            Token: token,
            User:  user.Sanitize(),
        },
        Timestamp: time.Now().Unix(),
        RequestID: getRequestID(r),
    }
    
    sendJSONResponse(w, response, http.StatusOK)
}

// ProtectedHandler handles GET /api/protected (example of a protected endpoint)
func (h *APIHandler) ProtectedHandler(w http.ResponseWriter, r *http.Request) {
    // Get user information from context
    userID := r.Context().Value("user_id")
    username := r.Context().Value("username")
    roles := r.Context().Value("roles")
    
    // Send success response
    response := models.SuccessResponse{
        Message: "Access granted to protected resource",
        Data: map[string]interface{}{
            "user_id":  userID,
            "username": username,
            "roles":    roles,
        },
        Timestamp: time.Now().Unix(),
        RequestID: getRequestID(r),
    }
    
    sendJSONResponse(w, response, http.StatusOK)
}
```

3. Update the APIHandler struct to include the authService:

```go
// Find the APIHandler struct definition
type APIHandler struct {
    userService UserServiceInterface
    mathService MathServiceInterface
    authService services.AuthServiceInterface // ADD THIS LINE
}
```

4. Update the NewAPIHandler function to include the authService:

```go
func NewAPIHandler(userService UserServiceInterface, mathService MathServiceInterface, authService services.AuthServiceInterface) *APIHandler {
    return &APIHandler{
        userService: userService,
        mathService: mathService,
        authService: authService, // ADD THIS LINE
    }
}
```

#### Step 7: Update the Main Function

1. Open [`cmd/server/main.go`](cmd/server/main.go:1)
2. Add the necessary imports:

```go
import (
    // ... existing imports ...
    "time" // Add this import
)
```

3. Initialize the auth service:

```go
// Find where services are initialized
userService := services.NewUserService(nil)
mathService := services.NewMathService()
wsService := services.NewWebSocketService()

// ADD THIS LINE:
authService := services.NewAuthService(userService, config.JWTSecret, config.JWTExpiration)
```

4. Update the handler initialization:

```go
// Find where handlers are initialized
apiHandler := handlers.NewAPIHandler(userService, mathService, authService) // ADD authService
wsHandler := handlers.NewWebSocketHandler(wsService)
staticHandler := handlers.NewStaticHandler("./web")
```

5. Update the middleware chain to include authentication:

```go
handler := middleware.LoggingMiddleware(
    middleware.RecoveryMiddleware(
        middleware.CORSMiddleware(
            middleware.RequestIDMiddleware(
                middleware.AuthMiddleware(authService)(mux), // ADD THIS LINE
            ),
        ),
    ),
)
```

6. Add the new routes:

```go
// Find where routes are registered
mux.HandleFunc("/health", apiHandler.HealthCheck)
mux.HandleFunc("/api/users", apiHandler.UsersHandler)
mux.HandleFunc("/api/users/", apiHandler.UserHandler)
mux.HandleFunc("/api/calculate", apiHandler.CalculateHandler)
mux.HandleFunc("/api/goroutines", apiHandler.GoroutineHandler)
mux.HandleFunc("/ws", wsHandler.HandleWebSocket)
mux.HandleFunc("/api/users/request-password-reset", apiHandler.RequestPasswordResetHandler)
mux.HandleFunc("/api/users/reset-password", apiHandler.ResetPasswordHandler)
mux.HandleFunc("/api/users/stats", apiHandler.GetUserStatsHandler)

// ADD THESE NEW ROUTES:
mux.HandleFunc("/api/login", apiHandler.LoginHandler)
mux.HandleFunc("/api/protected", apiHandler.ProtectedHandler)

mux.Handle("/", staticHandler)
```

#### Step 8: Test Your Changes

1. Run the application:
```bash
go run cmd/server/main.go
```

2. Test the login endpoint:
```bash
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice_dev",
    "password": "password"
  }'
```

You should get a response like:
```json
{
  "message": "Login successful",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "id": 1,
      "username": "alice_dev",
      "first_name": "Alice",
      "last_name": "Johnson",
      "age": 25,
      "active": true,
      "created_at": "2025-09-06T20:00:00Z",
      "roles": ["user", "developer"],
      "profile": {
        "bio": "Senior Go developer with 5+ years experience",
        "location": "San Francisco, CA",
        "skills": ["Go", "Docker", "Kubernetes", "PostgreSQL"],
        "experience": 5
      }
    }
  },
  "timestamp": 1634567890,
  "request_id": "req_1234567890"
}
```

3. Copy the token from the response and test the protected endpoint:

```bash
curl -X GET http://localhost:8080/api/protected \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

You should get a response like:
```json
{
  "message": "Access granted to protected resource",
  "data": {
    "user_id": 1,
    "username": "alice_dev",
    "roles": ["user", "developer"]
  },
  "timestamp": 1634567890,
  "request_id": "req_1234567891"
}
```

4. Test without a token:
```bash
curl -X GET http://localhost:8080/api/protected
```

You should get a 401 Unauthorized error.

#### Key Concepts Explained

1. **JWT (JSON Web Token)**: JWT is a compact, URL-safe means of representing claims to be transferred between two parties. It's commonly used for authentication and authorization.

2. **Middleware**: The authentication middleware intercepts requests to protected endpoints, validates the JWT token, and adds user information to the request context.

3. **Context**: The context package in Go allows us to pass request-scoped values through our application. We use it to pass user information from the middleware to the handlers.

4. **Signing Method**: We use HMAC-SHA256 to sign our JWTs. This ensures that the tokens can't be tampered with without the secret key.

5. **Token Expiration**: JWTs include an expiration date to limit the time window in which a token can be used if it's compromised.

#### Troubleshooting

- **Import Errors**: If you get errors about missing imports, make sure you've added all the required packages to the import statements.
- **Compilation Error**: If you get an error about the `AuthServiceInterface` not being found, make sure you've defined it in [`internal/services/auth.go`](internal/services/auth.go:1).
- **Invalid Token**: If you get "Invalid or expired token" errors, make sure you're using the exact token from the login response, and that it hasn't expired (the default is 24 hours).
- **Configuration Error**: If you get errors about the JWT configuration, make sure you've added the JWT fields to the Config struct and updated the LoadConfig function.

### Exercise 4: Add Database Support

#### Objective

Replace the in-memory user storage with a real database (PostgreSQL) to persist data between application restarts.

#### What You'll Learn

- How to connect to a database in Go
- How to perform database operations
- How to use an ORM (Object-Relational Mapping) library
- How to manage database migrations

#### Background

Currently, the application stores user data in memory, which means all data is lost when the application restarts. We'll replace this with a PostgreSQL database to persist data permanently.

#### Step 1: Install Required Packages

First, we need to install the database driver and ORM library. We'll use GORM as our ORM.

1. Open your terminal and run:
```bash
go get -u gorm.io/gorm
go get -u github.com/lib/pq
```

#### Step 2: Update the Configuration

1. Open [`internal/config/config.go`](internal/config/config.go:1)
2. Update the database configuration fields:

```go
type Config struct {
    // ... existing fields ...
    
    // Database configuration
    DBHost     string        // Database host address
    DBPort     string        // Database port number
    DBName     string        // Database name
    DBUser     string        // Database username
    DBPassword string        // Database password
    DBSSLMode  string        // Database SSL mode (disable, require, verify-ca, verify-full)
    DBMaxConns int           // Maximum database connections
    DBMaxIdle  int           // Maximum idle database connections
}
```

3. Update the `LoadConfig` function to include database configuration:

```go
func LoadConfig() (*Config, error) {
    config := &Config{
        // ... existing configuration ...
        
        // Database configuration
        DBHost:     getEnvOrDefault("DB_HOST", "localhost"),
        DBPort:     getEnvOrDefault("DB_PORT", "5432"),
        DBName:     getEnvOrDefault("DB_NAME", "scholastic_go"),
        DBUser:     getEnvOrDefault("DB_USER", "postgres"),
        DBPassword: getEnvOrDefault("DB_PASSWORD", ""),
        DBSSLMode:  getEnvOrDefault("DB_SSLMODE", "disable"),
        DBMaxConns: getEnvIntOrDefault("DB_MAX_CONNS", 25),
        DBMaxIdle:  getEnvIntOrDefault("DB_MAX_IDLE", 5),
    }
    
    // ... rest of the function ...
}
```

#### Step 3: Update the User Model

1. Open [`internal/models/models.go`](internal/models/models.go:1)
2. Add GORM tags to the User struct:

```go
type User struct {
    ID        uint           `json:"id" gorm:"primaryKey"` // Primary key
    Username  string         `json:"username" gorm:"unique;not null"` // Unique username
    Email     string         `json:"email" gorm:"unique;not null"` // Unique email
    FirstName string         `json:"first_name" gorm:"not null"` // First name
    LastName  string         `json:"last_name" gorm:"not null"` // Last name
    Age       int            `json:"age"` // Age in years
    Active    bool           `json:"active" gorm:"default:true"` // Account status
    CreatedAt time.Time      `json:"created_at" gorm:"autoCreateTime"` // Account creation timestamp
    UpdatedAt time.Time      `json:"updated_at" gorm:"autoUpdateTime"` // Last update timestamp
    Roles     string         `json:"roles" gorm:"type:text"` // User roles/permissions (as JSON)
    Profile   *Profile       `json:"profile,omitempty" gorm:"serializer:json"` // Optional profile information
    ResetToken           string    `json:"-" gorm:"-"`                 // Password reset token (hidden from JSON and DB)
    ResetTokenExpiresAt  time.Time `json:"-" gorm:"-"`                 // When the reset token expires (hidden from JSON and DB)
    PhoneNumber string     `json:"phone_number"` // User's phone number
}
```

3. Update the Profile struct:

```go
type Profile struct {
    ID        uint   `json:"-" gorm:"primaryKey"` // Primary key (hidden from JSON)
    UserID    uint   `json:"-" gorm:"not null"` // Foreign key to User (hidden from JSON)
    Bio       string `json:"bio"` // User biography
    AvatarURL string `json:"avatar_url"` // Profile picture URL
    Location  string `json:"location"` // User location
    Website   string `json:"website"` // Personal website
    Interests string `json:"interests" gorm:"type:text"` // User interests (as JSON)
    Skills    string `json:"skills" gorm:"type:text"` // User skills (as JSON)
    Experience int   `json:"experience"` // Years of experience
}
```

4. Add the `TableName` method to specify the table name:

```go
// TableName specifies the table name for the User model
func (User) TableName() string {
    return "users"
}

// TableName specifies the table name for the Profile model
func (Profile) TableName() string {
    return "profiles"
}
```

#### Step 4: Create a Database Service

1. Create a new file [`internal/services/database.go`](internal/services/database.go:1) with the following content:

```go
package services

import (
    "fmt"
    "log"
    "time"
    
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
    "gorm.io/gorm/logger"
    
    "scholastic-go-tutorial/internal/config"
)

// DatabaseService handles database connections and migrations
type DatabaseService struct {
    DB *gorm.DB
}

// NewDatabaseService creates a new database service
func NewDatabaseService(cfg *config.Config) (*DatabaseService, error) {
    // Build DSN (Data Source Name)
    dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=UTC",
        cfg.DBHost, cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBPort, cfg.DBSSLMode)
    
    // Configure GORM logger
    newLogger := logger.New(
        log.New(log.Writer(), "\r\n", log.LstdFlags),
        logger.Config{
            SlowThreshold: time.Second,
            LogLevel:      logger.Info,
            Colorful:      false,
        },
    )
    
    // Open database connection
    db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
        Logger: newLogger,
    })
    
    if err != nil {
        return nil, fmt.Errorf("failed to connect to database: %w", err)
    }
    
    // Get underlying sql.DB to configure connection pool
    sqlDB, err := db.DB()
    if err != nil {
        return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
    }
    
    // Configure connection pool
    sqlDB.SetMaxIdleConns(cfg.DBMaxIdle)
    sqlDB.SetMaxOpenConns(cfg.DBMaxConns)
    
    // Test connection
    if err := sqlDB.Ping(); err != nil {
        return nil, fmt.Errorf("failed to ping database: %w", err)
    }
    
    log.Println("Database connection established successfully")
    
    return &DatabaseService{DB: db}, nil
}

// Close closes the database connection
func (ds *DatabaseService) Close() error {
    sqlDB, err := ds.DB.DB()
    if err != nil {
        return fmt.Errorf("failed to get underlying sql.DB: %w", err)
    }
    
    return sqlDB.Close()
}

// AutoMigrate runs database migrations
func (ds *DatabaseService) AutoMigrate(models ...interface{}) error {
    return ds.DB.AutoMigrate(models...)
}
```

#### Step 5: Update the User Service

1. Open [`internal/services/services.go`](internal/services/services.go:1)
2. Update the UserService struct to use the database:

```go
type UserService struct {
    db *gorm.DB // Database connection
}
```

3. Update the NewUserService function:

```go
func NewUserService(db *gorm.DB) *UserService {
    service := &UserService{
        db: db,
    }
    
    // Initialize with some sample users for demonstration
    service.initializeSampleUsers()
    
    return service
}
```

4. Update all the UserService methods to use GORM:

```go
func (s *UserService) GetUserByID(id int) (*models.User, error) {
    var user models.User
    result := s.db.First(&user, id)
    if result.Error != nil {
        if result.Error == gorm.ErrRecordNotFound {
            return nil, fmt.Errorf("user with ID %d not found", id)
        }
        return nil, fmt.Errorf("failed to get user: %w", result.Error)
    }
    
    return &user, nil
}

func (s *UserService) GetAllUsers() ([]*models.User, error) {
    var users []*models.User
    result := s.db.Find(&users)
    if result.Error != nil {
        return nil, fmt.Errorf("failed to get all users: %w", result.Error)
    }
    
    return users, nil
}

func (s *UserService) CreateUser(user *models.User) error {
    // Validate user data
    if err := user.ValidateCreate(); err != nil {
        return fmt.Errorf("user validation failed: %w", err)
    }
    
    result := s.db.Create(user)
    if result.Error != nil {
        return fmt.Errorf("failed to create user: %w", result.Error)
    }
    
    return nil
}

func (s *UserService) UpdateUser(user *models.User) error {
    if err := user.ValidateUpdate(); err != nil {
        return fmt.Errorf("user validation failed: %w", err)
    }
    
    result := s.db.Save(user)
    if result.Error != nil {
        return fmt.Errorf("failed to update user: %w", result.Error)
    }
    
    return nil
}

func (s *UserService) DeleteUser(id int) error {
    result := s.db.Delete(&models.User{}, id)
    if result.Error != nil {
        return fmt.Errorf("failed to delete user: %w", result.Error)
    }
    
    if result.RowsAffected == 0 {
        return fmt.Errorf("user with ID %d not found", id)
    }
    
    return nil
}

func (s *UserService) GetUserByUsername(username string) (*models.User, error) {
    var user models.User
    result := s.db.Where("username = ?", username).First(&user)
    if result.Error != nil {
        if result.Error == gorm.ErrRecordNotFound {
            return nil, fmt.Errorf("user with username '%s' not found", username)
        }
        return nil, fmt.Errorf("failed to get user by username: %w", result.Error)
    }
    
    return &user, nil
}

func (s *UserService) SearchUsers(query string) ([]*models.User, error) {
    var users []*models.User
    
    query = strings.ToLower(strings.TrimSpace(query))
    if query == "" {
        return s.GetAllUsers()
    }
    
    result := s.db.Where(
        "LOWER(username) LIKE ? OR LOWER(first_name) LIKE ? OR LOWER(last_name) LIKE ? OR LOWER(email) LIKE ?",
        "%"+query+"%", "%"+query+"%", "%"+query+"%", "%"+query+"%",
    ).Find(&users)
    
    if result.Error != nil {
        return nil, fmt.Errorf("failed to search users: %w", result.Error)
    }
    
    return users, nil
}

func (s *UserService) GetUserStats() (*models.UserStats, error) {
    var stats models.UserStats
    
    // Get total users count
    if err := s.db.Model(&models.User{}).Count(&stats.TotalUsers).Error; err != nil {
        return nil, fmt.Errorf("failed to get total users count: %w", err)
    }
    
    // Get active users count
    if err := s.db.Model(&models.User{}).Where("active = ?", true).Count(&stats.ActiveUsers).Error; err != nil {
        return nil, fmt.Errorf("failed to get active users count: %w", err)
    }
    
    // Get inactive users count
    if err := s.db.Model(&models.User{}).Where("active = ?", false).Count(&stats.InactiveUsers).Error; err != nil {
        return nil, fmt.Errorf("failed to get inactive users count: %w", err)
    }
    
    // Get average age
    if err := s.db.Model(&models.User{}).Select("AVG(age)").Scan(&stats.AverageAge).Error; err != nil {
        return nil, fmt.Errorf("failed to get average age: %w", err)
    }
    
    return &stats, nil
}

func (s *UserService) RequestPasswordReset(email string) error {
    // Find user by email
    var user models.User
    result := s.db.Where("email = ?", email).First(&user)
    if result.Error != nil {
        if result.Error == gorm.ErrRecordNotFound {
            return fmt.Errorf("user with email '%s' not found", email)
        }
        return fmt.Errorf("failed to find user: %w", result.Error)
    }
    
    // Generate a secure random token
    token, err := s.generateSecureToken()
    if err != nil {
        return fmt.Errorf("failed to generate reset token: %w", err)
    }
    
    // Set token and expiration (24 hours from now)
    user.ResetToken = token
    user.ResetTokenExpiresAt = time.Now().Add(24 * time.Hour)
    
    // Update the user
    result = s.db.Save(&user)
    if result.Error != nil {
        return fmt.Errorf("failed to update user: %w", result.Error)
    }
    
    // In a real application, you would send an email with the token
    // For this example, we'll just log it
    log.Printf("Password reset token for %s: %s", user.Email, token)
    
    return nil
}

func (s *UserService) ResetPassword(token, newPassword string) error {
    // Validate inputs
    if strings.TrimSpace(token) == "" {
        return fmt.Errorf("token cannot be empty")
    }
    
    if strings.TrimSpace(newPassword) == "" {
        return fmt.Errorf("new password cannot be empty")
    }
    
    if len(newPassword) < 8 {
        return fmt.Errorf("new password must be at least 8 characters long")
    }
    
    // Find user by reset token
    var user models.User
    result := s.db.Where("reset_token = ?", token).First(&user)
    if result.Error != nil {
        if result.Error == gorm.ErrRecordNotFound {
            return fmt.Errorf("invalid reset token")
        }
        return fmt.Errorf("failed to find user: %w", result.Error)
    }
    
    // Check if token is expired
    if time.Now().After(user.ResetTokenExpiresAt) {
        return fmt.Errorf("reset token has expired")
    }
    
    // In a real application, you would hash the password here
    // For this example, we'll just store it as-is (not secure for production!)
    
    // Clear the reset token and update the user
    user.ResetToken = ""
    user.ResetTokenExpiresAt = time.Time{}
    user.UpdatedAt = time.Now()
    
    result = s.db.Save(&user)
    if result.Error != nil {
        return fmt.Errorf("failed to update user: %w", result.Error)
    }
    
    log.Printf("Password reset successful for user %s", user.Email)
    
    return nil
}

func (s *UserService) ValidateResetToken(token string) (*models.User, error) {
    if strings.TrimSpace(token) == "" {
        return nil, fmt.Errorf("token cannot be empty")
    }
    
    var user models.User
    result := s.db.Where("reset_token = ?", token).First(&user)
    if result.Error != nil {
        if result.Error == gorm.ErrRecordNotFound {
            return nil, fmt.Errorf("invalid reset token")
        }
        return nil, fmt.Errorf("failed to find user: %w", result.Error)
    }
    
    // Check if token is expired
    if time.Now().After(user.ResetTokenExpiresAt) {
        return nil, fmt.Errorf("reset token has expired")
    }
    
    return &user, nil
}

func (s *UserService) generateSecureToken() (string, error) {
    // In a real application, you would use a cryptographically secure random generator
    // For this example, we'll use a simple approach
    b := make([]byte, 32)
    _, err := rand.Read(b)
    if err != nil {
        return "", err
    }
    return fmt.Sprintf("%x", b), nil
}

func (s *UserService) initializeSampleUsers() {
    // Check if users already exist
    var count int64
    s.db.Model(&models.User{}).Count(&count)
    if count > 0 {
        return // Users already exist, no need to initialize
    }
    
    sampleUsers := []*models.User{
        {
            Username:  "alice_dev",
            Email:     "alice@example.com",
            FirstName: "Alice",
            LastName:  "Johnson",
            Age:       25,
            Active:    true,
            Roles:     "user,developer",
            PhoneNumber: "+1 (555) 123-4567",
            Profile: &models.Profile{
                Bio:       "Senior Go developer with 5+ years experience",
                Location:  "San Francisco, CA",
                Skills:    "Go,Docker,Kubernetes,PostgreSQL",
                Experience: 5,
            },
        },
        {
            Username:  "bob_coder",
            Email:     "bob@example.com",
            FirstName: "Bob",
            LastName:  "Smith",
            Age:       30,
            Active:    true,
            Roles:     "user,developer",
            PhoneNumber: "+44 20 7946 0958",
            Profile: &models.Profile{
                Bio:       "Full-stack developer passionate about clean code",
                Location:  "Austin, TX",
                Skills:    "JavaScript,React,Node.js,MongoDB",
                Experience: 3,
            },
        },
        {
            Username:  "charlie_go",
            Email:     "charlie@example.com",
            FirstName: "Charlie",
            LastName:  "Brown",
            Age:       35,
            Active:    true,
            Roles:     "user,developer,mentor",
            PhoneNumber: "+81 3-1234-5678",
            Profile: &models.Profile{
                Bio:       "Go enthusiast and open source contributor",
                Location:  "Seattle, WA",
                Skills:    "Go,Python,AWS,Microservices",
                Experience: 7,
            },
        },
        {
            Username:  "diana_admin",
            Email:     "diana@example.com",
            FirstName: "Diana",
            LastName:  "Wilson",
            Age:       40,
            Active:    true,
            Roles:     "user,admin",
            PhoneNumber: "+61 2 9876 5432",
            Profile: &models.Profile{
                Bio:       "System administrator and DevOps engineer",
                Location:  "New York, NY",
                Skills:    "Linux,AWS,Docker,CI/CD",
                Experience: 6,
            },
        },
        {
            Username:  "eve_tester",
            Email:     "eve@example.com",
            FirstName: "Eve",
            LastName:  "Davis",
            Age:       28,
            Active:    true,
            Roles:     "user,tester",
            PhoneNumber: "+49 30 12345678",
            Profile: &models.Profile{
                Bio:       "QA engineer focused on automation testing",
                Location:  "Chicago, IL",
                Skills:    "Selenium,Python,Jest,Cypress",
                Experience: 4,
            },
        },
    }
    
    for _, user := range sampleUsers {
        if err := s.db.Create(user).Error; err != nil {
            log.Printf("Failed to create sample user %s: %v", user.Username, err)
        }
    }
}
```

#### Step 6: Update the Main Function

1. Open [`cmd/server/main.go`](cmd/server/main.go:1)
2. Add the necessary imports:

```go
import (
    // ... existing imports ...
    "gorm.io/gorm" // Add this import
)
```

3. Update the main function to initialize the database:

```go
func main() {
    // ... existing code until service initialization ...
    
    // Initialize database
    dbService, err := services.NewDatabaseService(config)
    if err != nil {
        log.Fatalf("❌ Failed to initialize database: %v", err)
    }
    defer dbService.Close()
    
    // Run database migrations
    if err := dbService.AutoMigrate(
        &models.User{},
        &models.Profile{},
    ); err != nil {
        log.Fatalf("❌ Failed to run database migrations: %v", err)
    }
    
    // Initialize services
    userService := services.NewUserService(dbService.DB)
    mathService := services.NewMathService()
    wsService := services.NewWebSocketService()
    authService := services.NewAuthService(userService, config.JWTSecret, config.JWTExpiration)
    
    // ... rest of the main function ...
}
```

#### Step 7: Set Up PostgreSQL

Before running the application, you need to set up a PostgreSQL database:

1. Install PostgreSQL if you haven't already:
   - On Ubuntu: `sudo apt-get install postgresql postgresql-contrib`
   - On macOS: `brew install postgresql`
   - On Windows: Download from the official PostgreSQL website

2. Start the PostgreSQL service:
   - On Ubuntu: `sudo service postgresql start`
   - On macOS: `brew services start postgresql`
   - On Windows: The service should start automatically after installation

3. Create a database and user:
```bash
sudo -u postgres psql
```

In the psql shell:
```sql
CREATE DATABASE scholastic_go;
CREATE USER scholastic_user WITH PASSWORD 'scholastic_password';
GRANT ALL PRIVILEGES ON DATABASE scholastic_go TO scholastic_user;
\q
```

4. Set environment variables for the database connection:
```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=scholastic_go
export DB_USER=scholastic_user
export DB_PASSWORD=scholastic_password
export DB_SSLMODE=disable
```

#### Step 8: Test Your Changes

1. Run the application:
```bash
go run cmd/server/main.go
```

2. Test creating a new user:
```bash
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "newuser@example.com",
    "first_name": "New",
    "last_name": "User",
    "age": 25,
    "phone_number": "+1 (555) 987-6543"
  }'
```

3. Stop the application and restart it:
```bash
# Press Ctrl+C to stop the application
go run cmd/server/main.go
```

4. Test retrieving all users:
```bash
curl -X GET http://localhost:8080/api/users
```

You should see the user you created in step 2, which means the data was persisted in the database.

#### Key Concepts Explained

1. **ORM (Object-Relational Mapping)**: GORM is an ORM library for Go that simplifies database operations by allowing you to work with Go structs instead of writing SQL queries directly.

2. **Database Migrations**: The `AutoMigrate` function automatically creates or updates database tables based on your Go structs. This is useful for development but should be replaced with proper migration scripts in production.

3. **Connection Pooling**: We configured the database connection pool to limit the number of open connections, which is important for performance and resource management.

4. **Model Struct Tags**: GORM uses struct tags to configure how fields are mapped to database columns. For example, `gorm:"primaryKey"` marks a field as the primary key.

5. **Foreign Key Relationships**: The Profile struct includes a UserID field that acts as a foreign key to the User table, establishing a one-to-one relationship between users and profiles.

#### Troubleshooting

- **Connection Error**: If you get an error connecting to the database, check that PostgreSQL is running and that your connection parameters are correct.
- **Migration Error**: If you get an error running migrations, make sure your model structs are correctly defined with the right GORM tags.
- **Permission Error**: If you get a permission error, make sure the database user has the necessary permissions to create and modify tables.
- **Port Already in Use**: If you get an error that the port is already in use, make sure you've stopped any previous instances of the application.

## Intermediate Exercises

### Exercise 5: Implement WebSockets

#### Objective

Replace the simulated WebSocket functionality with real WebSocket connections for real-time communication.

#### What You'll Learn

- How to implement real WebSocket connections
- How to handle WebSocket messages
- How to manage WebSocket connection lifecycle
- How to broadcast messages to connected clients

#### Background

Currently, the application simulates WebSocket functionality using HTTP endpoints. We'll replace this with real WebSocket connections to enable true real-time communication.

#### Step 1: Install Required Packages

First, we need to install a WebSocket library for Go. We'll use the popular `github.com/gorilla/websocket` package.

1. Open your terminal and run:
```bash
go get github.com/gorilla/websocket
```

#### Step 2: Update the WebSocket Service

1. Open [`internal/services/services.go`](internal/services/services.go:1)
2. Replace the WebSocketService implementation with a real one:

```go
// Replace the entire WebSocketService implementation

/*
WEBSOCKET SERVICE IMPLEMENTATION
Implements real WebSocket functionality
*/

type WebSocketService struct {
    connections map[string]*websocket.Conn // User ID to WebSocket connection mapping
    mu          sync.RWMutex              // Mutex for connection access
    upgrader    websocket.Upgrader          // WebSocket upgrader
}

// NewWebSocketService creates a new WebSocketService instance
func NewWebSocketService() *WebSocketService {
    return &WebSocketService{
        connections: make(map[string]*websocket.Conn),
        upgrader: websocket.Upgrader{
            ReadBufferSize:  1024,
            WriteBufferSize: 1024,
            CheckOrigin: func(r *http.Request) bool {
                // Allow all connections in development
                // In production, you should implement proper origin checking
                return true
            },
        },
    }
}

// RegisterUser registers a user for WebSocket communication
func (s *WebSocketService) RegisterUser(userID string, conn *websocket.Conn) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    if _, exists := s.connections[userID]; exists {
        return fmt.Errorf("user %s is already registered", userID)
    }
    
    s.connections[userID] = conn
    return nil
}

// UnregisterUser removes a user from WebSocket communication
func (s *WebSocketService) UnregisterUser(userID string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    conn, exists := s.connections[userID]
    if !exists {
        return fmt.Errorf("user %s is not registered", userID)
    }
    
    // Close the connection
    if err := conn.Close(); err != nil {
        log.Printf("Error closing WebSocket connection for user %s: %v", userID, err)
    }
    
    // Remove the connection
    delete(s.connections, userID)
    
    return nil
}

// BroadcastMessage sends a message to all connected users
func (s *WebSocketService) BroadcastMessage(message models.WSMessage) error {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    if len(s.connections) == 0 {
        return fmt.Errorf("no users connected")
    }
    
    // Marshal message to JSON
    messageJSON, err := json.Marshal(message)
    if err != nil {
        return fmt.Errorf("failed to marshal message: %w", err)
    }
    
    // Send message to all users concurrently
    var wg sync.WaitGroup
    errors := make(chan error, len(s.connections))
    
    for userID, conn := range s.connections {
        wg.Add(1)
        go func(id string, c *websocket.Conn) {
            defer wg.Done()
            
            // Set write deadline
            if err := c.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
                errors <- fmt.Errorf("failed to set write deadline for user %s: %w", id, err)
                return
            }
            
            // Write message
            if err := c.WriteMessage(websocket.TextMessage, messageJSON); err != nil {
                errors <- fmt.Errorf("failed to write message to user %s: %w", id, err)
            }
        }(userID, conn)
    }
    
    wg.Wait()
    close(errors)
    
    // Check for any errors
    var errorMessages []string
    for err := range errors {
        errorMessages = append(errorMessages, err.Error())
    }
    
    if len(errorMessages) > 0 {
        return fmt.Errorf("broadcast failed for some users: %v", errorMessages)
    }
    
    return nil
}

// SendMessage sends a message to a specific user
func (s *WebSocketService) SendMessage(userID string, message models.WSMessage) error {
    s.mu.RLock()
    conn, exists := s.connections[userID]
    s.mu.RUnlock()
    
    if !exists {
        return fmt.Errorf("user %s is not connected", userID)
    }
    
    // Marshal message to JSON
    messageJSON, err := json.Marshal(message)
    if err != nil {
        return fmt.Errorf("failed to marshal message: %w", err)
    }
    
    // Set write deadline
    if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
        return fmt.Errorf("failed to set write deadline for user %s: %w", userID, err)
    }
    
    // Write message
    if err := conn.WriteMessage(websocket.TextMessage, messageJSON); err != nil {
        return fmt.Errorf("failed to write message to user %s: %w", userID, err)
    }
    
    return nil
}

// GetConnectedUsers returns a list of all connected user IDs
func (s *WebSocketService) GetConnectedUsers() []string {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    userIDs := make([]string, 0, len(s.connections))
    for userID := range s.connections {
        userIDs = append(userIDs, userID)
    }
    
    return userIDs
}

// HandleConnection handles a WebSocket connection
func (s *WebSocketService) HandleConnection(w http.ResponseWriter, r *http.Request, userID string) {
    // Upgrade HTTP connection to WebSocket
    conn, err := s.upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Printf("Failed to upgrade connection for user %s: %v", userID, err)
        return
    }
    defer conn.Close()
    
    // Register the user
    if err := s.RegisterUser(userID, conn); err != nil {
        log.Printf("Failed to register user %s: %v", userID, err)
        return
    }
    defer s.UnregisterUser(userID)
    
    log.Printf("WebSocket connection established for user %s", userID)
    
    // Send welcome message
    welcomeMessage := models.WSMessage{
        Type:      "system",
        From:      "server",
        Content:   json.RawMessage(`{"text": "Welcome to the real-time chat!"}`),
        Timestamp: time.Now().Unix(),
        ID:        fmt.Sprintf("msg_%d", time.Now().UnixNano()),
    }
    
    if err := s.SendMessage(userID, welcomeMessage); err != nil {
        log.Printf("Failed to send welcome message to user %s: %v", userID, err)
    }
    
    // Message handling loop
    for {
        // Set read deadline
        if err := conn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
            log.Printf("Failed to set read deadline for user %s: %v", userID, err)
            break
        }
        
        // Read message
        messageType, messageData, err := conn.ReadMessage()
        if err != nil {
            if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
                log.Printf("WebSocket connection closed unexpectedly for user %s: %v", userID, err)
            }
            break
        }
        
        // Handle different message types
        if messageType == websocket.TextMessage {
            var message models.WSMessage
            if err := json.Unmarshal(messageData, &message); err != nil {
                log.Printf("Failed to unmarshal message from user %s: %v", userID, err)
                continue
            }
            
            // Set message metadata
            message.From = userID
            message.Timestamp = time.Now().Unix()
            
            if message.ID == "" {
                message.ID = fmt.Sprintf("msg_%d", time.Now().UnixNano())
            }
            
            // Broadcast the message to all connected users
            if err := s.BroadcastMessage(message); err != nil {
                log.Printf("Failed to broadcast message from user %s: %v", userID, err)
            }
        }
    }
    
    log.Printf("WebSocket connection closed for user %s", userID)
}
```

#### Step 3: Update the WebSocket Handler

1. Open [`internal/handlers/handlers.go`](internal/handlers/handlers.go:1)
2. Replace the WebSocketHandler implementation:

```go
// Replace the entire WebSocketHandler implementation

/*
WEBSOCKET HANDLER
Handles real WebSocket connections
*/

// HandleWebSocket handles WebSocket upgrade and message exchange
func (h *WebSocketHandler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
    // Extract user ID from query parameters
    userID := r.URL.Query().Get("user_id")
    if userID == "" {
        sendErrorResponse(w, "User ID is required", "MISSING_USER_ID", 
            http.StatusBadRequest, getRequestID(r))
        return
    }
    
    // Handle the WebSocket connection
    h.wsService.HandleConnection(w, r, userID)
}
```

#### Step 4: Create a Simple WebSocket Client

For testing purposes, let's create a simple HTML client that can connect to our WebSocket server.

1. Create a new file [`web/websocket.html`](web/websocket.html:1) with the following content:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebSocket Chat</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        #messages {
            border: 1px solid #ccc;
            padding: 10px;
            height: 300px;
            overflow-y: scroll;
            margin-bottom: 20px;
        }
        .message {
            margin-bottom: 10px;
            padding: 5px;
            border-radius: 5px;
        }
        .system {
            background-color: #f0f0f0;
            color: #666;
        }
        .user {
            background-color: #e3f2fd;
            color: #1976d2;
        }
        .input-container {
            display: flex;
            gap: 10px;
        }
        #messageInput {
            flex: 1;
            padding: 5px;
        }
        button {
            padding: 5px 10px;
            background-color: #1976d2;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }
        button:hover {
            background-color: #1565c0;
        }
    </style>
</head>
<body>
    <h1>WebSocket Chat</h1>
    <div id="messages"></div>
    <div class="input-container">
        <input type="text" id="messageInput" placeholder="Type a message...">
        <button onclick="sendMessage()">Send</button>
    </div>

    <script>
        // Get user ID from URL parameters
        const urlParams = new URLSearchParams(window.location.search);
        const userId = urlParams.get('user_id') || 'anonymous';
        
        // Connect to WebSocket
        const ws = new WebSocket(`ws://localhost:8080/ws?user_id=${userId}`);
        
        // Handle incoming messages
        ws.onmessage = function(event) {
            const message = JSON.parse(event.data);
            displayMessage(message);
        };
        
        // Handle connection open
        ws.onopen = function(event) {
            console.log('WebSocket connection established');
        };
        
        // Handle connection close
        ws.onclose = function(event) {
            console.log('WebSocket connection closed');
        };
        
        // Handle connection error
        ws.onerror = function(error) {
            console.error('WebSocket error:', error);
        };
        
        // Send message function
        function sendMessage() {
            const input = document.getElementById('messageInput');
            const messageText = input.value.trim();
            
            if (messageText) {
                const message = {
                    type: 'chat',
                    content: {
                        text: messageText,
                        channel: 'general',
                        message_type: 'text'
                    }
                };
                
                ws.send(JSON.stringify(message));
                input.value = '';
            }
        }
        
        // Display message function
        function displayMessage(message) {
            const messagesDiv = document.getElementById('messages');
            const messageDiv = document.createElement('div');
            
            if (message.type === 'system') {
                messageDiv.className = 'message system';
                
                const content = JSON.parse(message.content);
                messageDiv.textContent = `[System] ${content.text}`;
            } else {
                messageDiv.className = 'message user';
                
                const content = JSON.parse(message.content);
                messageDiv.textContent = `[${message.from}] ${content.text}`;
            }
            
            messagesDiv.appendChild(messageDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
        }
        
        // Handle Enter key in input field
        document.getElementById('messageInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
    </script>
</body>
</html>
```

#### Step 5: Test Your Implementation

1. Run the application:
```bash
go run cmd/server/main.go
```

2. Open two browser tabs and navigate to:
```
http://localhost:8080/websocket.html?user_id=user1
http://localhost:8080/websocket.html?user_id=user2
```

3. Send messages from one tab and observe them appearing in both tabs in real-time.

#### Key Concepts Explained

1. **WebSocket Protocol**: WebSocket is a communication protocol that provides full-duplex communication channels over a single TCP connection. It's designed for real-time web applications.

2. **Connection Upgrade**: The HTTP connection is "upgraded" to a WebSocket connection using the `Upgrade` header. This is handled by the `websocket.Upgrader`.

3. **Message Handling**: The server reads messages from the WebSocket connection, processes them, and can broadcast them to other connected clients.

4. **Concurrency**: WebSocket connections are handled concurrently using goroutines, allowing the server to handle many connections simultaneously.

5. **Connection Lifecycle**: The server manages the lifecycle of WebSocket connections, including registration, message handling, and cleanup when connections are closed.

#### Troubleshooting

- **Connection Error**: If you get an error connecting to the WebSocket, make sure the server is running and that you're using the correct URL.
- **CORS Error**: If you get a CORS error, make sure your CORS middleware is configured correctly to allow WebSocket connections.
- **Message Not Received**: If messages aren't being received, check that the JSON marshaling/unmarshaling is working correctly and that there are no errors in the server logs.
- **Connection Timeout**: If connections are timing out, check that the read/write deadlines are set appropriately and that there are no network issues.

### Exercise 6: Add Rate Limiting

#### Objective

Implement IP-based rate limiting with Redis to prevent abuse of your API endpoints.

#### What You'll Learn

- How to integrate Redis with Go applications
- How to implement rate limiting algorithms
- How to use middleware for cross-cutting concerns
- How to configure rate limiting rules

#### Background

Rate limiting is an important technique to prevent abuse of your API by limiting the number of requests a client can make in a specific time window. We'll implement IP-based rate limiting using Redis as a distributed store.

#### Step 1: Install Required Packages

First, we need to install a Redis client for Go.

1. Open your terminal and run:
```bash
go get github.com/go-redis/redis/v8
```

#### Step 2: Update the Configuration

1. Open [`internal/config/config.go`](internal/config/config.go:1)
2. Add rate limiting configuration fields to the Config struct:

```go
type Config struct {
    // ... existing fields ...
    
    // Rate limiting configuration
    EnableRateLimit bool   `json:"enable_rate_limit"` // Enable rate limiting
    RateLimitRPS    int    `json:"rate_limit_rps"`    // Requests per second per IP
    RateLimitBurst  int    `json:"rate_limit_burst"`  // Burst size for rate limiting
    RedisHost       string `json:"redis_host"`       // Redis host
    RedisPort       string `json:"redis_port"`       // Redis port
    RedisPassword   string `json:"redis_password"`   // Redis password
    RedisDB         int    `json:"redis_db"`         // Redis database number
}
```

3. Update the `LoadConfig` function to include rate limiting configuration:

```go
func LoadConfig() (*Config, error) {
    config := &Config{
        // ... existing configuration ...
        
        // Rate limiting configuration
        EnableRateLimit: getEnvBoolOrDefault("ENABLE_RATE_LIMIT", true),
        RateLimitRPS:    getEnvIntOrDefault("RATE_LIMIT_RPS", 10),
        RateLimitBurst:  getEnvIntOrDefault("RATE_LIMIT_BURST", 20),
        RedisHost:       getEnvOrDefault("REDIS_HOST", "localhost"),
        RedisPort:       getEnvOrDefault("REDIS_PORT", "6379"),
        RedisPassword:   getEnvOrDefault("REDIS_PASSWORD", ""),
        RedisDB:         getEnvIntOrDefault("REDIS_DB", 0),
    }
    
    // ... rest of the function ...
}
```

#### Step 3: Create a Rate Limiting Service

1. Create a new file [`internal/services/ratelimiter.go`](internal/services/ratelimiter.go:1) with the following content:

```go
package services

import (
   "context"
   "fmt"
   "strconv"
   "time"
    
    "github.com/go-redis/redis/v8"
)

// RateLimiterService handles rate limiting logic
type RateLimiterService struct {
    redisClient *redis.Client
}

// NewRateLimiterService creates a new RateLimiterService instance
func NewRateLimiterService(host, port, password string, db int) *RateLimiterService {
    rdb := redis.NewClient(&redis.Options{
        Addr:     fmt.Sprintf("%s:%s", host, port),
        Password: password,
        DB:       db,
    })
    
    return &RateLimiterService{
        redisClient: rdb,
    }
}

// RateLimiterServiceInterface defines the contract for rate limiting operations
type RateLimiterServiceInterface interface {
    IsAllowed(ip string, limit int, window time.Duration) (bool, error)
    Close() error
}

// IsAllowed checks if a request from the given IP is allowed
func (s *RateLimiterService) IsAllowed(ip string, limit int, window time.Duration) (bool, error) {
    ctx := context.Background()
    
    // Create a key for the IP
    key := fmt.Sprintf("rate_limit:%s", ip)
    
    // Get the current count
    count, err := s.redisClient.Get(ctx, key).Int()
    if err == redis.Nil {
        // Key doesn't exist, set it to 1 with expiration
        err := s.redisClient.Set(ctx, key, 1, window).Err()
        if err != nil {
            return false, fmt.Errorf("failed to set rate limit key: %w", err)
        }
        return true, nil
    } else if err != nil {
        return false, fmt.Errorf("failed to get rate limit count: %w", err)
    }
    
    // Check if the count exceeds the limit
    if count >= limit {
        return false, nil
    }
    
    // Increment the count
    err = s.redisClient.Incr(ctx, key).Err()
    if err != nil {
        return false, fmt.Errorf("failed to increment rate limit count: %w", err)
    }
    
    return true, nil
}

// Close closes the Redis connection
func (s *RateLimiterService) Close() error {
    return s.redisClient.Close()
}

// SlidingWindowRateLimiter implements a more sophisticated rate limiting algorithm
type SlidingWindowRateLimiter struct {
    redisClient *redis.Client
}

// NewSlidingWindowRateLimiter creates a new SlidingWindowRateLimiter instance
func NewSlidingWindowRateLimiter(host, port, password string, db int) *SlidingWindowRateLimiter {
    rdb := redis.NewClient(&redis.Options{
        Addr:     fmt.Sprintf("%s:%s", host, port),
        Password: password,
        DB:       db,
    })
    
    return &SlidingWindowRateLimiter{
        redisClient: rdb,
    }
}

// IsAllowed checks if a request from the given IP is allowed using a sliding window algorithm
func (s *SlidingWindowRateLimiter) IsAllowed(ip string, limit int, window time.Duration) (bool, error) {
    ctx := context.Background()
    
    // Create a key for the IP
    key := fmt.Sprintf("sliding_rate_limit:%s", ip)
    
    // Current timestamp
    now := time.Now().Unix()
    
    // Remove old entries outside the window
    minTimestamp := now - int64(window.Seconds())
    s.redisClient.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(minTimestamp, 10))
    
    // Add current request
    s.redisClient.ZAdd(ctx, key, &redis.Z{
        Score:  float64(now),
        Member: strconv.FormatInt(now, 10),
    })
    
    // Set expiration on the key
    s.redisClient.Expire(ctx, key, window)
    
    // Count requests in the window
    count, err := s.redisClient.ZCount(ctx, key, strconv.FormatInt(minTimestamp, 10), strconv.FormatInt(now, 10)).Result()
    if err != nil {
        return false, fmt.Errorf("failed to count requests in sliding window: %w", err)
    }
    
    return count <= int64(limit), nil
}

// Close closes the Redis connection
func (s *SlidingWindowRateLimiter) Close() error {
    return s.redisClient.Close()
}
```

#### Step 4: Update the Rate Limiting Middleware

1. Open [`internal/middleware/middleware.go`](internal/middleware/middleware.go:1)
2. Replace the existing rate limiting middleware with a Redis-based one:

```go
// Replace the existing RateLimiter and RateLimitMiddleware implementation

/*
REDIS-BASED RATE LIMITING MIDDLEWARE
Implements IP-based rate limiting with Redis
*/

// RedisRateLimitMiddleware creates a Redis-based rate limiting middleware
func RedisRateLimitMiddleware(rateLimiter services.RateLimiterServiceInterface, limit int, window time.Duration) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Get client IP address
            clientIP := getClientIP(r)
            
            // Check rate limit
            allowed, err := rateLimiter.IsAllowed(clientIP, limit, window)
            if err != nil {
                log.Printf("[RateLimit] Error checking rate limit for IP %s: %v", clientIP, err)
                // Continue processing if there's an error with rate limiting
                next.ServeHTTP(w, r)
                return
            }
            
            if !allowed {
                requestID := getRequestIDFromContext(r)
                log.Printf("[RateLimit] Rate limit exceeded for IP %s (Request ID: %s)", clientIP, requestID)
                
                // Send rate limit exceeded response
                w.Header().Set("Content-Type", "application/json")
                w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
                w.Header().Set("X-RateLimit-Remaining", "0")
                w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(window).Unix()))
                w.WriteHeader(http.StatusTooManyRequests)
                
                fmt.Fprintf(w, `{"error": "Rate limit exceeded", "code": "RATE_LIMIT_EXCEEDED", "message": "Too many requests. Please try again later."}`)
                return
            }
            
            // Add rate limit headers
            w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
            w.Header().Set("X-RateLimit-Remaining", "1") // Simplified for this example
            
            // Call next handler
            next.ServeHTTP(w, r)
        })
    }
}
```

#### Step 5: Update the Main Function

1. Open [`cmd/server/main.go`](cmd/server/main.go:1)
2. Add the necessary imports:

```go
import (
    // ... existing imports ...
    "time" // Add this import if not already present
)
```

3. Initialize the rate limiter service:

```go
// Find where services are initialized
userService := services.NewUserService(dbService.DB)
mathService := services.NewMathService()
wsService := services.NewWebSocketService()
authService := services.NewAuthService(userService, config.JWTSecret, config.JWTExpiration)

// ADD THIS CODE:
var rateLimiter services.RateLimiterServiceInterface
if config.EnableRateLimit {
    rateLimiter = services.NewRateLimiterService(
        config.RedisHost,
        config.RedisPort,
        config.RedisPassword,
        config.RedisDB,
    )
    defer rateLimiter.Close()
    
    // Test Redis connection
    if err := rateLimiter.(*services.RateLimiterService).redisClient.Ping(context.Background()).Err(); err != nil {
        log.Printf("Warning: Failed to connect to Redis, rate limiting will be disabled: %v", err)
        rateLimiter = nil
    }
}
```

4. Update the middleware chain to include rate limiting:

```go
// Find the middleware chain configuration
handler := middleware.LoggingMiddleware(
    middleware.RecoveryMiddleware(
        middleware.CORSMiddleware(
            middleware.RequestIDMiddleware(
                middleware.AuthMiddleware(authService)(
                    func(next http.Handler) http.Handler {
                        if rateLimiter != nil {
                            return middleware.RedisRateLimitMiddleware(rateLimiter, config.RateLimitRPS, time.Second)(next)
                        }
                        return next
                    }(mux),
                ),
            ),
        ),
    ),
)
```

#### Step 6: Set Up Redis

Before running the application, you need to set up a Redis server:

1. Install Redis if you haven't already:
   - On Ubuntu: `sudo apt-get install redis-server`
   - On macOS: `brew install redis`
   - On Windows: Download from the official Redis website

2. Start the Redis server:
   - On Ubuntu: `sudo service redis-server start`
   - On macOS: `brew services start redis`
   - On Windows: The service should start automatically after installation

3. Set environment variables for the Redis connection (optional, if using non-default settings):
```bash
export REDIS_HOST=localhost
export REDIS_PORT=6379
export REDIS_PASSWORD=
export REDIS_DB=0
```

#### Step 7: Test Your Implementation

1. Run the application:
```bash
go run cmd/server/main.go
```

2. Test rate limiting by sending requests rapidly:

```bash
# Create a simple script to test rate limiting
for i in {1..15}; do
    curl -X GET http://localhost:8080/health
    echo "Request $i completed"
    sleep 0.1
done
```

You should see the first 10 requests succeed, and the next 5 fail with a 429 Too Many Responses error.

#### Key Concepts Explained

1. **Rate Limiting**: Rate limiting is a technique to control the rate of traffic sent or received by a server. It's used to prevent abuse, manage resource usage, and ensure fair access.

2. **Redis**: Redis is an in-memory data structure store, used as a database, cache, and message broker. We use it to store rate limiting counters because it's fast and can be shared across multiple instances of our application.

3. **Fixed Window vs. Sliding Window**: The simple rate limiter uses a fixed window algorithm, which counts requests in fixed time windows. The sliding window algorithm provides more accurate rate limiting by tracking requests in a sliding time window.

4. **Distributed Rate Limiting**: By using Redis, we can implement distributed rate limiting that works across multiple instances of our application, which is important for scalability.

5. **Headers**: We include rate limiting headers in the response to inform clients about their current rate limit status, which is a best practice for API design.

#### Troubleshooting

- **Redis Connection Error**: If you get an error connecting to Redis, make sure Redis is running and that your connection parameters are correct.
- **Rate Limiting Not Working**: If rate limiting doesn't seem to be working, check that the `ENABLE_RATE_LIMIT` environment variable is set to `true` and that there are no errors in the server logs.
- **All Requests Blocked**: If all requests are being blocked, check that your rate limit settings are reasonable (e.g., not too low) and that Redis is storing and retrieving counters correctly.

### Exercise 7: Create Unit Tests

#### Objective

Write comprehensive unit tests for the services to ensure they work correctly and to prevent regressions.

#### What You'll Learn

- How to write unit tests in Go
- How to use the testing package
- How to create test doubles (mocks and stubs)
- How to use test assertions

#### Background

Unit tests are automated tests that verify the correctness of individual units of code (such as functions or methods) in isolation. They're essential for maintaining code quality and preventing regressions.

#### Step 1: Create Test Files

In Go, test files are created by adding `_test.go` to the name of the file being tested. For example, tests for `services.go` would be in `services_test.go`.

1. Create a test file for the services:
```bash
touch internal/services/services_test.go
```

2. Create a test file for the models:
```bash
touch internal/models/models_test.go
```

#### Step 2: Write Tests for the User Model

1. Open [`internal/models/models_test.go`](internal/models/models_test.go:1) and add the following content:

```go
package models

import (
    "testing"
    "time"
)

func TestUserValidate(t *testing.T) {
    tests := []struct {
        name    string
        user    *User
        wantErr bool
        errMsg  string
    }{
        {
            name: "Valid user",
            user: &User{
                Username:  "validuser",
                Email:     "valid@example.com",
                FirstName: "Valid",
                LastName:  "User",
                Age:       25,
                Roles:     []string{"user"},
            },
            wantErr: false,
        },
        {
            name: "Empty username",
            user: &User{
                Username:  "",
                Email:     "valid@example.com",
                FirstName: "Valid",
                LastName:  "User",
                Age:       25,
                Roles:     []string{"user"},
            },
            wantErr: true,
            errMsg:  "username cannot be empty",
        },
        {
            name: "Invalid email",
            user: &User{
                Username:  "validuser",
                Email:     "invalid-email",
                FirstName: "Valid",
                LastName:  "User",
                Age:       25,
                Roles:     []string{"user"},
            },
            wantErr: true,
            errMsg:  "invalid email format",
        },
        {
            name: "Empty first name",
            user: &User{
                Username:  "validuser",
                Email:     "valid@example.com",
                FirstName: "",
                LastName:  "User",
                Age:       25,
                Roles:     []string{"user"},
            },
            wantErr: true,
            errMsg:  "first name cannot be empty",
        },
        {
            name: "Negative age",
            user: &User{
                Username:  "validuser",
                Email:     "valid@example.com",
                FirstName: "Valid",
                LastName:  "User",
                Age:       -1,
                Roles:     []string{"user"},
            },
            wantErr: true,
            errMsg:  "age cannot be negative",
        },
        {
            name: "No roles",
            user: &User{
                Username:  "validuser",
                Email:     "valid@example.com",
                FirstName: "Valid",
                LastName:  "User",
                Age:       25,
                Roles:     []string{},
            },
            wantErr: true,
            errMsg:  "user must have at least one role",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := tt.user.Validate()
            if (err != nil) != tt.wantErr {
                t.Errorf("User.Validate() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if tt.wantErr && err.Error() != tt.errMsg {
                t.Errorf("User.Validate() error message = %v, want %v", err.Error(), tt.errMsg)
            }
        })
    }
}

func TestUserValidateCreate(t *testing.T) {
    tests := []struct {
        name    string
        user    *User
        wantErr bool
        errMsg  string
    }{
        {
            name: "Valid user for creation",
            user: &User{
                Username:  "newuser",
                Email:     "new@example.com",
                FirstName: "New",
                LastName:  "User",
                Age:       25,
                Roles:     []string{"user"},
            },
            wantErr: false,
        },
        {
            name: "User with ID set",
            user: &User{
                ID:        1,
                Username:  "newuser",
                Email:     "new@example.com",
                FirstName: "New",
                LastName:  "User",
                Age:       25,
                Roles:     []string{"user"},
            },
            wantErr: true,
            errMsg:  "ID must be zero for new user",
        },
        {
            name: "User with CreatedAt set",
            user: &User{
                Username:  "newuser",
                Email:     "new@example.com",
                FirstName: "New",
                LastName:  "User",
                Age:       25,
                Roles:     []string{"user"},
                CreatedAt: time.Now(),
            },
            wantErr: true,
            errMsg:  "created_at must be zero for new user",
        },
        {
            name: "User with UpdatedAt set",
            user: &User{
                Username:  "newuser",
                Email:     "new@example.com",
                FirstName: "New",
                LastName:  "User",
                Age:       25,
                Roles:     []string{"user"},
                UpdatedAt: time.Now(),
            },
            wantErr: true,
            errMsg:  "updated_at must be zero for new user",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := tt.user.ValidateCreate()
            if (err != nil) != tt.wantErr {
                t.Errorf("User.ValidateCreate() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if tt.wantErr && err.Error() != tt.errMsg {
                t.Errorf("User.ValidateCreate() error message = %v, want %v", err.Error(), tt.errMsg)
            }
        })
    }
}

func TestUserValidateUpdate(t *testing.T) {
    tests := []struct {
        name    string
        user    *User
        wantErr bool
        errMsg  string
    }{
        {
            name: "Valid user for update",
            user: &User{
                ID:        1,
                Username:  "existinguser",
                Email:     "existing@example.com",
                FirstName: "Existing",
                LastName:  "User",
                Age:       25,
                Roles:     []string{"user"},
            },
            wantErr: false,
        },
        {
            name: "User with zero ID",
            user: &User{
                ID:        0,
                Username:  "existinguser",
                Email:     "existing@example.com",
                FirstName: "Existing",
                LastName:  "User",
                Age:       25,
                Roles:     []string{"user"},
            },
            wantErr: true,
            errMsg:  "ID must be positive for update",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := tt.user.ValidateUpdate()
            if (err != nil) != tt.wantErr {
                t.Errorf("User.ValidateUpdate() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if tt.wantErr && err.Error() != tt.errMsg {
                t.Errorf("User.ValidateUpdate() error message = %v, want %v", err.Error(), tt.errMsg)
            }
        })
    }
}

func TestUserGetFullName(t *testing.T) {
    user := &User{
        FirstName: "John",
        LastName:  "Doe",
    }
    
    expected := "John Doe"
    actual := user.GetFullName()
    
    if actual != expected {
        t.Errorf("User.GetFullName() = %v, want %v", actual, expected)
    }
}

func TestUserHasRole(t *testing.T) {
    user := &User{
        Roles: []string{"user", "admin"},
    }
    
    tests := []struct {
        name     string
        role     string
        expected bool
    }{
        {
            name:     "User has role",
            role:     "user",
            expected: true,
        },
        {
            name:     "User has admin role",
            role:     "admin",
            expected: true,
        },
        {
            name:     "User doesn't have role",
            role:     "superuser",
            expected: false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            actual := user.HasRole(tt.role)
            if actual != tt.expected {
                t.Errorf("User.HasRole(%v) = %v, want %v", tt.role, actual, tt.expected)
            }
        })
    }
}

func TestUserAddRole(t *testing.T) {
    user := &User{
        Roles: []string{"user"},
    }
    
    user.AddRole("admin")
    
    if !user.HasRole("admin") {
        t.Error("Expected user to have admin role after adding it")
    }
    
    // Adding the same role again should not duplicate it
    user.AddRole("admin")
    
    count := 0
    for _, role := range user.Roles {
        if role == "admin" {
            count++
        }
    }
    
    if count != 1 {
        t.Errorf("Expected admin role to appear exactly once, got %d times", count)
    }
}

func TestUserRemoveRole(t *testing.T) {
    user := &User{
        Roles: []string{"user", "admin", "moderator"},
    }
    
    user.RemoveRole("admin")
    
    if user.HasRole("admin") {
        t.Error("Expected user to not have admin role after removing it")
    }
    
    if !user.HasRole("user") {
        t.Error("Expected user to still have user role after removing admin role")
    }
    
    if !user.HasRole("moderator") {
        t.Error("Expected user to still have moderator role after removing admin role")
    }
}

func TestUserIsAdult(t *testing.T) {
    tests := []struct {
        name     string
        age      int
        expected bool
    }{
        {
            name:     "Child",
            age:      17,
            expected: false,
        },
        {
            name:     "Adult",
            age:      18,
            expected: true,
        },
        {
            name:     "Senior",
            age:      65,
            expected: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            user := &User{
                Age: tt.age,
            }
            
            actual := user.IsAdult()
            if actual != tt.expected {
                t.Errorf("User.IsAdult() with age %d = %v, want %v", tt.age, actual, tt.expected)
            }
        })
    }
}

func TestUserGetAgeGroup(t *testing.T) {
    tests := []struct {
        name     string
        age      int
        expected string
    }{
        {
            name:     "Child",
            age:      12,
            expected: "child",
        },
        {
            name:     "Teenager",
            age:      15,
            expected: "teenager",
        },
        {
            name:     "Adult",
            age:      25,
            expected: "adult",
        },
        {
            name:     "Senior",
            age:      70,
            expected: "senior",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            user := &User{
                Age: tt.age,
            }
            
            actual := user.GetAgeGroup()
            if actual != tt.expected {
                t.Errorf("User.GetAgeGroup() with age %d = %v, want %v", tt.age, actual, tt.expected)
            }
        })
    }
}

func TestUserSanitize(t *testing.T) {
    user := &User{
        ID:        1,
        Username:  "testuser",
        Email:     "test@example.com",
        FirstName: "Test",
        LastName:  "User",
        Age:       25,
        Active:    true,
        CreatedAt: time.Now(),
        Roles:     []string{"user", "admin"},
        Profile: &Profile{
            Bio:       "Test bio",
            Location:  "Test location",
            Skills:    []string{"Go", "Docker"},
            Experience: 5,
        },
    }
    
    sanitized := user.Sanitize()
    
    // Check that sensitive fields are removed
    if sanitized.Email != "" {
        t.Error("Expected email to be removed in sanitized user")
    }
    
    // Check that other fields are preserved
    if sanitized.ID != user.ID {
        t.Errorf("Expected ID to be preserved, got %d, want %d", sanitized.ID, user.ID)
    }
    
    if sanitized.Username != user.Username {
        t.Errorf("Expected username to be preserved, got %v, want %v", sanitized.Username, user.Username)
    }
    
    if sanitized.FirstName != user.FirstName {
        t.Errorf("Expected first name to be preserved, got %v, want %v", sanitized.FirstName, user.FirstName)
    }
    
    if sanitized.LastName != user.LastName {
        t.Errorf("Expected last name to be preserved, got %v, want %v", sanitized.LastName, user.LastName)
    }
    
    if sanitized.Age != user.Age {
        t.Errorf("Expected age to be preserved, got %d, want %d", sanitized.Age, user.Age)
    }
    
    if sanitized.Active != user.Active {
        t.Errorf("Expected active to be preserved, got %v, want %v", sanitized.Active, user.Active)
    }
}
```

#### Step 3: Write Tests for the User Service

1. Open [`internal/services/services_test.go`](internal/services/services_test.go:1) and add the following content:

```go
package services

import (
    "testing"
    "time"
    
    "scholastic-go-tutorial/internal/models"
)

// MockUserService is a mock implementation of UserServiceInterface for testing
type MockUserService struct {
    users map[int]*models.User
    nextID int
}

func NewMockUserService() *MockUserService {
    service := &MockUserService{
        users:  make(map[int]*models.User),
        nextID: 1,
    }
    
    // Add a sample user for testing
    user := models.NewUser("testuser", "test@example.com", "Test", "User", "+1 (555) 123-4567")
    user.ID = service.nextID
    service.nextID++
    service.users[user.ID] = user
    
    return service
}

func (m *MockUserService) GetUserByID(id int) (*models.User, error) {
    user, exists := m.users[id]
    if !exists {
        return nil, fmt.Errorf("user with ID %d not found", id)
    }
    
    userCopy := *user
    return &userCopy, nil
}

func (m *MockUserService) GetAllUsers() ([]*models.User, error) {
    users := make([]*models.User, 0, len(m.users))
    for _, user := range m.users {
        userCopy := *user
        users = append(users, &userCopy)
    }
    
    return users, nil
}

func (m *MockUserService) CreateUser(user *models.User) error {
    if err := user.ValidateCreate(); err != nil {
        return fmt.Errorf("user validation failed: %w", err)
    }
    
    // Check if username already exists
    for _, existingUser := range m.users {
        if existingUser.Username == user.Username {
            return fmt.Errorf("username '%s' already exists", user.Username)
        }
        if existingUser.Email == user.Email {
            return fmt.Errorf("email '%s' already exists", user.Email)
        }
    }
    
    user.ID = m.nextID
    m.nextID++
    user.CreatedAt = time.Now()
    user.UpdatedAt = time.Now()
    
    m.users[user.ID] = user
    
    return nil
}

func (m *MockUserService) UpdateUser(user *models.User) error {
    if err := user.ValidateUpdate(); err != nil {
        return fmt.Errorf("user validation failed: %w", err)
    }
    
    if _, exists := m.users[user.ID]; !exists {
        return fmt.Errorf("user with ID %d not found", user.ID)
    }
    
    user.UpdatedAt = time.Now()
    m.users[user.ID] = user
    
    return nil
}

func (m *MockUserService) DeleteUser(id int) error {
    if _, exists := m.users[id]; !exists {
        return fmt.Errorf("user with ID %d not found", id)
    }
    
    delete(m.users, id)
    return nil
}

func (m *MockUserService) GetUserByUsername(username string) (*models.User, error) {
    for _, user := range m.users {
        if user.Username == username {
            userCopy := *user
            return &userCopy, nil
        }
    }
    
    return nil, fmt.Errorf("user with username '%s' not found", username)
}

func (m *MockUserService) SearchUsers(query string) ([]*models.User, error) {
    var results []*models.User
    for _, user := range m.users {
        // Simple search implementation for testing
        results = append(results, user)
    }
    
    return results, nil
}

func (m *MockUserService) GetUserStats() (*models.UserStats, error) {
    stats := &models.UserStats{
        TotalUsers:    len(m.users),
        ActiveUsers:   len(m.users),
        InactiveUsers: 0,
        AverageAge:    25, // Simplified for testing
    }
    
    return stats, nil
}

func (m *MockUserService) RequestPasswordReset(email string) error {
    return nil // Simplified for testing
}

func (m *MockUserService) ResetPassword(token, newPassword string) error {
    return nil // Simplified for testing
}

func (m *MockUserService) ValidateResetToken(token string) (*models.User, error) {
    return nil, fmt.Errorf("not implemented") // Simplified for testing
}

func TestUserService_GetUserByID(t *testing.T) {
    service := NewMockUserService()
    
    // Test getting an existing user
    user, err := service.GetUserByID(1)
    if err != nil {
        t.Errorf("GetUserByID(1) returned error: %v", err)
    }
    
    if user == nil {
        t.Error("GetUserByID(1) returned nil user")
    }
    
    if user.ID != 1 {
        t.Errorf("GetUserByID(1) returned user with ID %d, want 1", user.ID)
    }
    
    // Test getting a non-existent user
    user, err = service.GetUserByID(999)
    if err == nil {
        t.Error("GetUserByID(999) should return error")
    }
    
    if user != nil {
        t.Error("GetUserByID(999) should return nil user")
    }
}

func TestUserService_GetAllUsers(t *testing.T) {
    service := NewMockUserService()
    
    users, err := service.GetAllUsers()
    if err != nil {
        t.Errorf("GetAllUsers() returned error: %v", err)
    }
    
    if len(users) != 1 {
        t.Errorf("GetAllUsers() returned %d users, want 1", len(users))
    }
    
    if users[0].ID != 1 {
        t.Errorf("GetAllUsers() returned user with ID %d, want 1", users[0].ID)
    }
}

func TestUserService_CreateUser(t *testing.T) {
    service := NewMockUserService()
    
    // Test creating a valid user
    newUser := &models.User{
        Username:  "newtestuser",
        Email:     "newtest@example.com",
        FirstName: "New",
        LastName:  "Test",
        Age:       25,
        PhoneNumber: "+1 (555) 987-6543",
    }
    
    err := service.CreateUser(newUser)
    if err != nil {
        t.Errorf("CreateUser() returned error: %v", err)
    }
    
    if newUser.ID == 0 {
        t.Error("Expected CreateUser to set ID")
    }
    
    // Verify the user was created
    createdUser, err := service.GetUserByID(newUser.ID)
    if err != nil {
        t.Errorf("Failed to get created user: %v", err)
    }
    
    if createdUser.Username != newUser.Username {
        t.Errorf("Created user username mismatch: got %s, want %s", createdUser.Username, newUser.Username)
    }
    
    // Test creating user with invalid data
    invalidUser := &models.User{
        Username:  "invaliduser",
        Email:     "invalid-email",
        FirstName: "Invalid",
        LastName:  "User",
        Age:       25,
    }
    
    err = service.CreateUser(invalidUser)
    if err == nil {
        t.Error("Expected CreateUser to return validation error for invalid email")
    }
    
    if err.Error() != "user validation failed: invalid email format" {
        t.Errorf("Expected specific validation error, got: %v", err)
    }
    
    // Test duplicate username
    duplicateUser := &models.User{
        Username:  "testuser", // Same as the initial sample user
        Email:     "duplicate@example.com",
        FirstName: "Duplicate",
        LastName:  "User",
        Age:       30,
    }
    
    err = service.CreateUser(duplicateUser)
    if err == nil {
        t.Error("Expected CreateUser to return error for duplicate username")
    }
    
    if err.Error() != "username 'testuser' already exists" {
        t.Errorf("Expected duplicate username error, got: %v", err)
    }
}

// TestUserService_UpdateUser tests updating an existing user
func TestUserService_UpdateUser(t *testing.T) {
    service := NewMockUserService()
    
    // Create a user to update
    user := &models.User{
        ID:        1,
        Username:  "updateuser",
        Email:     "update@example.com",
        FirstName: "Update",
        LastName:  "User",
        Age:       25,
    }
    service.users[1] = user
    
    // Test updating with valid data
    user.Age = 30
    user.FirstName = "Updated"
    
    err := service.UpdateUser(user)
    if err != nil {
        t.Errorf("UpdateUser() returned error: %v", err)
    }
    
    // Verify the user was updated
    updatedUser, err := service.GetUserByID(1)
    if err != nil {
        t.Errorf("Failed to get updated user: %v", err)
    }
    
    if updatedUser.Age != 30 {
        t.Errorf("User age was not updated, got %d, want 30", updatedUser.Age)
    }
    
    if updatedUser.FirstName != "Updated" {
        t.Errorf("User first name was not updated, got %s, want Updated", updatedUser.FirstName)
    }
    
    // Test updating non-existent user
    nonExistentUser := &models.User{
        ID:        999,
        Username:  "nonexistent",
        Email:     "nonexistent@example.com",
        FirstName: "Non",
        LastName:  "Existent",
        Age:       40,
    }
    
    err = service.UpdateUser(nonExistentUser)
    if err == nil {
        t.Error("Expected UpdateUser to return error for non-existent user")
    }
    
    if err.Error() != "user with ID 999 not found" {
        t.Errorf("Expected specific error for non-existent user, got: %v", err)
    }
    
    // Test updating with invalid data
    invalidUser := &models.User{
        ID:        1,
        Username:  "",
        Email:     "update@example.com",
        FirstName: "Update",
        LastName:  "User",
        Age:       30,
    }
    
    err = service.UpdateUser(invalidUser)
    if err == nil {
        t.Error("Expected UpdateUser to return validation error for empty username")
    }
    
    if err.Error() != "user validation failed: username cannot be empty" {
        t.Errorf("Expected specific validation error, got: %v", err)
    }
}

// TestUserService_DeleteUser tests deleting a user
func TestUserService_DeleteUser(t *testing.T) {
    service := NewMockUserService()
    
    // Test deleting an existing user
    err := service.DeleteUser(1)
    if err != nil {
        t.Errorf("DeleteUser(1) returned error: %v", err)
    }
    
    // Verify the user was deleted
    _, err = service.GetUserByID(1)
    if err == nil {
        t.Error("Expected GetUserByID(1) to return error after deletion")
    }
    
    if err.Error() != "user with ID 1 not found" {
        t.Errorf("Expected specific error after deletion, got: %v", err)
    }
    
    // Test deleting a non-existent user
    err = service.DeleteUser(999)
    if err == nil {
        t.Error("Expected DeleteUser to return error for non-existent user")
    }
    
    if err.Error() != "user with ID 999 not found" {
        t.Errorf("Expected specific error for non-existent user, got: %v", err)
    }
}

// TestUserService_GetUserByUsername tests getting user by username
func TestUserService_GetUserByUsername(t *testing.T) {
    service := NewMockUserService()
    
    // Test getting existing user by username
    user, err := service.GetUserByUsername("testuser")
    if err != nil {
        t.Errorf("GetUserByUsername('testuser') returned error: %v", err)
    }
    
    if user.Username != "testuser" {
        t.Errorf("GetUserByUsername('testuser') returned wrong user: %s", user.Username)
    }
    
    // Test getting non-existent user by username
    user, err = service.GetUserByUsername("nonexistent")
    if err == nil {
        t.Error("Expected GetUserByUsername to return error for non-existent user")
    }
    
    if user != nil {
        t.Error("Expected GetUserByUsername to return nil for non-existent user")
    }
    
    if err.Error() != "user with username 'nonexistent' not found" {
        t.Errorf("Expected specific error for non-existent username, got: %v", err)
    }
}

// TestUserService_SearchUsers tests searching users
func TestUserService_SearchUsers(t *testing.T) {
    service := NewMockUserService()
    
    // Test searching with valid query
    users, err := service.SearchUsers("test")
    if err != nil {
        t.Errorf("SearchUsers('test') returned error: %v", err)
    }
    
    if len(users) != 1 {
        t.Errorf("SearchUsers('test') returned %d users, expected 1", len(users))
    }
    
    // Test searching with empty query (should return all users)
    users, err = service.SearchUsers("")
    if err != nil {
        t.Errorf("SearchUsers('') returned error: %v", err)
    }
    
    if len(users) != 1 {
        t.Errorf("SearchUsers('') returned %d users, expected 1", len(users))
    }
}

// TestUserService_GetUserStats tests getting user statistics
func TestUserService_GetUserStats(t *testing.T) {
    service := NewMockUserService()
    
    stats, err := service.GetUserStats()
    if err != nil {
        t.Errorf("GetUserStats() returned error: %v", err)
    }
    
    if stats.TotalUsers != 1 {
        t.Errorf("GetUserStats() returned total_users %d, expected 1", stats.TotalUsers)
    }
    
    if stats.ActiveUsers != 1 {
        t.Errorf("GetUserStats() returned active_users %d, expected 1", stats.ActiveUsers)
    }
    
    if stats.InactiveUsers != 0 {
        t.Errorf("GetUserStats() returned inactive_users %d, expected 0", stats.InactiveUsers)
    }
    
    if stats.AverageAge != 25 {
        t.Errorf("GetUserStats() returned average_age %d, expected 25", stats.AverageAge)
    }
}

// TestUserService_RequestPasswordReset tests password reset request
func TestUserService_RequestPasswordReset(t *testing.T) {
    service := NewMockUserService()
    
    // Add a user with email for testing
    user := &models.User{
        ID:        2,
        Username:  "resetuser",
        Email:     "reset@example.com",
        FirstName: "Reset",
        LastName:  "User",
        Age:       25,
    }
    service.users[2] = user
    
    err := service.RequestPasswordReset("reset@example.com")
    if err != nil {
        t.Errorf("RequestPasswordReset('reset@example.com') returned error: %v", err)
    }
    
    // Verify the token was set (in real implementation, check database)
    if user.ResetToken == "" {
        t.Error("Expected RequestPasswordReset to set reset token")
    }
    
    if user.ResetTokenExpiresAt.IsZero() {
        t.Error("Expected RequestPasswordReset to set expiration time")
    }
    
    // Test with non-existent email
    err = service.RequestPasswordReset("nonexistent@example.com")
    if err == nil {
        t.Error("Expected RequestPasswordReset to return error for non-existent email")
    }
    
    if err.Error() != "user with email 'nonexistent@example.com' not found" {
        t.Errorf("Expected specific error for non-existent email, got: %v", err)
    }
}

// TestUserService_ResetPassword tests password reset
func TestUserService_ResetPassword(t *testing.T) {
    service := NewMockUserService()
    
    // Add a user with reset token for testing
    user := &models.User{
        ID:        3,
        Username:  "resetpwuser",
        Email:     "resetpw@example.com",
        FirstName: "ResetPW",
        LastName:  "User",
        Age:       25,
        ResetToken: "testtoken",
        ResetTokenExpiresAt: time.Now().Add(1 * time.Hour),
    }
    service.users[3] = user
    
    err := service.ResetPassword("testtoken", "newpassword123")
    if err != nil {
        t.Errorf("ResetPassword('testtoken', 'newpassword123') returned error: %v", err)
    }
    
    // Verify token was cleared
    updatedUser, err := service.GetUserByID(3)
    if err != nil {
        t.Errorf("Failed to get user after reset: %v", err)
    }
    
    if updatedUser.ResetToken != "" {
        t.Error("Expected ResetPassword to clear reset token")
    }
    
    if updatedUser.ResetTokenExpiresAt.IsZero() {
        t.Error("Expected ResetPassword to clear expiration time")
    }
    
    // Test with invalid token
    err = service.ResetPassword("invalidtoken", "newpassword")
    if err == nil {
        t.Error("Expected ResetPassword to return error for invalid token")
    }
    
    if err.Error() != "invalid reset token" {
        t.Errorf("Expected specific error for invalid token, got: %v", err)
    }
    
    // Test with expired token
    expiredUser := &models.User{
        ID:        4,
        Username:  "expireduser",
        Email:     "expired@example.com",
        FirstName: "Expired",
        LastName:  "User",
        Age:       25,
        ResetToken: "expiredtoken",
        ResetTokenExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
    }
    service.users[4] = expiredUser
    
    err = service.ResetPassword("expiredtoken", "newpassword")
    if err == nil {
        t.Error("Expected ResetPassword to return error for expired token")
    }
    
    if err.Error() != "reset token has expired" {
        t.Errorf("Expected specific error for expired token, got: %v", err)
    }
}

// TestUserService_ValidateResetToken tests token validation
func TestUserService_ValidateResetToken(t *testing.T) {
    service := NewMockUserService()
    
    // Add a user with valid token
    user := &models.User{
        ID:        5,
        Username:  "validtokenuser",
        Email:     "validtoken@example.com",
        FirstName: "ValidToken",
        LastName:  "User",
        Age:       25,
        ResetToken: "validtoken",
        ResetTokenExpiresAt: time.Now().Add(1 * time.Hour),
    }
    service.users[5] = user
    
    validatedUser, err := service.ValidateResetToken("validtoken")
    if err != nil {
        t.Errorf("ValidateResetToken('validtoken') returned error: %v", err)
    }
    
    if validatedUser.ID != 5 {
        t.Errorf("ValidateResetToken returned wrong user")
    }
    
    // Test with invalid token
    _, err = service.ValidateResetToken("invalidtoken")
    if err == nil {
        t.Error("Expected ValidateResetToken to return error for invalid token")
    }
    
    if err.Error() != "invalid reset token" {
        t.Errorf("Expected specific error for invalid token, got: %v", err)
    }
    
    // Test with expired token
    expiredUser := &models.User{
        ID:        6,
        Username:  "expiredtokenuser",
        Email:     "expiredtoken@example.com",
        FirstName: "ExpiredToken",
        LastName:  "User",
        Age:       25,
        ResetToken: "expiredtoken",
        ResetTokenExpiresAt: time.Now().Add(-1 * time.Hour),
    }
    service.users[6] = expiredUser
    
    _, err = service.ValidateResetToken("expiredtoken")
    if err == nil {
        t.Error("Expected ValidateResetToken to return error for expired token")
    }
    
    if err.Error() != "reset token has expired" {
        t.Errorf("Expected specific error for expired token, got: %v", err)
    }
}

// Test running the tests
func TestMain(m *testing.M) {
    // Set up any test setup here
    os.Exit(m.Run())
}

// TestUserService_UpdateUser tests updating an existing user
func TestUserService_UpdateUser(t *testing.T) {
    service := NewMockUserService()
    
    // Create a user to update
    user := &models.User{
        ID:        1,
        Username:  "updateuser",
        Email:     "update@example.com",
        FirstName: "Update",
        LastName:  "User",
        Age:       25,
    }
    service.users[1] = user
    
    // Test updating with valid data
    user.Age = 30
    user.FirstName = "Updated"
    
    err := service.UpdateUser(user)
    if err != nil {
        t.Errorf("UpdateUser() returned error: %v", err)
    }
    
    // Verify the user was updated
    updatedUser, err := service.GetUserByID(1)
    if err != nil {
        t.Errorf("Failed to get updated user: %v", err)
    }
    
    if updatedUser.Age != 30 {
        t.Errorf("User age was not updated, got %d, want 30", updatedUser.Age)
    }
    
    if updatedUser.FirstName != "Updated" {
        t.Errorf("User first name was not updated, got %s, want Updated", updatedUser.FirstName)
    }
    
    // Test updating non-existent user
    nonExistentUser := &models.User{
        ID:        999,
        Username:  "nonexistent",
        Email:     "nonexistent@example.com",
        FirstName: "Non",
        LastName:  "Existent",
        Age:       40,
    }
    
    err = service.UpdateUser(nonExistentUser)
    if err == nil {
        t.Error("Expected UpdateUser to return error for non-existent user")
    }
    
    if err.Error() != "user with ID 999 not found" {
        t.Errorf("Expected specific error for non-existent user, got: %v", err)
    }
    
    // Test updating with invalid data
    invalidUser := &models.User{
        ID:        1,
        Username:  "",
        Email:     "update@example.com",
        FirstName: "Update",
        LastName:  "User",
        Age:       30,
    }
    
    err = service.UpdateUser(invalidUser)
    if err == nil {
        t.Error("Expected UpdateUser to return validation error for empty username")
    }
    
    if err.Error() != "user validation failed: username cannot be empty" {
        t.Errorf("Expected specific validation error, got: %v", err)
    }
}

// TestUserService_DeleteUser tests deleting a user
func TestUserService_DeleteUser(t *testing.T) {
    service := NewMockUserService()
    
    // Test deleting an existing user
    err := service.DeleteUser(1)
    if err != nil {
        t.Errorf("DeleteUser(1) returned error: %v", err)
    }
    
    // Verify the user was deleted
    _, err = service.GetUserByID(1)
    if err == nil {
        t.Error("Expected GetUserByID(1) to return error after deletion")
    }
    
    if err.Error() != "user with ID 1 not found" {
        t.Errorf("Expected specific error after deletion, got: %v", err)
    }
    
    // Test deleting a non-existent user
    err = service.DeleteUser(999)
    if err == nil {
        t.Error("Expected DeleteUser to return error for non-existent user")
    }
    
    if err.Error() != "user with ID 999 not found" {
        t.Errorf("Expected specific error for non-existent user, got: %v", err)
    }
}

// TestUserService_GetUserByUsername tests getting user by username
func TestUserService_GetUserByUsername(t *testing.T) {
    service := NewMockUserService()
    
    // Test getting existing user by username
    user, err := service.GetUserByUsername("testuser")
    if err != nil {
        t.Errorf("GetUserByUsername('testuser') returned error: %v", err)
    }
    
    if user.Username != "testuser" {
        t.Errorf("GetUserByUsername('testuser') returned wrong user: %s", user.Username)
    }
    
    // Test getting non-existent user by username
    user, err = service.GetUserByUsername("nonexistent")
    if err == nil {
        t.Error("Expected GetUserByUsername to return error for non-existent user")
    }
    
    if user != nil {
        t.Error("Expected GetUserByUsername to return nil for non-existent user")
    }
    
    if err.Error() != "user with username 'nonexistent' not found" {
        t.Errorf("Expected specific error for non-existent username, got: %v", err)
    }
}

// TestUserService_SearchUsers tests searching users
func TestUserService_SearchUsers(t *testing.T) {
    service := NewMockUserService()
    
    // Test searching with valid query
    users, err := service.SearchUsers("test")
    if err != nil {
        t.Errorf("SearchUsers('test') returned error: %v", err)
    }
    
    if len(users) != 1 {
        t.Errorf("SearchUsers('test') returned %d users, expected 1", len(users))
    }
    
    // Test searching with empty query (should return all users)
    users, err = service.SearchUsers("")
    if err != nil {
        t.Errorf("SearchUsers('') returned error: %v", err)
    }
    
    if len(users) != 1 {
        t.Errorf("SearchUsers('') returned %d users, expected 1", len(users))
    }
}

// TestUserService_GetUserStats tests getting user statistics
func TestUserService_GetUserStats(t *testing.T) {
    service := NewMockUserService()
    
    stats, err := service.GetUserStats()
    if err != nil {
        t.Errorf("GetUserStats() returned error: %v", err)
    }
    
    if stats.TotalUsers != 1 {
        t.Errorf("GetUserStats() returned total_users %d, expected 1", stats.TotalUsers)
    }
    
    if stats.ActiveUsers != 1 {
        t.Errorf("GetUserStats() returned active_users %d, expected 1", stats.ActiveUsers)
    }
    
    if stats.InactiveUsers != 0 {
        t.Errorf("GetUserStats() returned inactive_users %d, expected 0", stats.InactiveUsers)
    }
    
    if stats.AverageAge != 25 {
        t.Errorf("GetUserStats() returned average_age %d, expected 25", stats.AverageAge)
    }
}

// TestUserService_RequestPasswordReset tests password reset request
func TestUserService_RequestPasswordReset(t *testing.T) {
    service := NewMockUserService()
    
    // Add a user with email for testing
    user := &models.User{
        ID:        2,
        Username:  "resetuser",
        Email:     "reset@example.com",
        FirstName: "Reset",
        LastName:  "User",
        Age:       25,
    }
    service.users[2] = user
    
    err := service.RequestPasswordReset("reset@example.com")
    if err != nil {
        t.Errorf("RequestPasswordReset('reset@example.com') returned error: %v", err)
    }
    
    // Verify the token was set (in real implementation, check database)
    if user.ResetToken == "" {
        t.Error("Expected RequestPasswordReset to set reset token")
    }
    
    if user.ResetTokenExpiresAt.IsZero() {
        t.Error("Expected RequestPasswordReset to set expiration time")
    }
    
    // Test with non-existent email
    err = service.RequestPasswordReset("nonexistent@example.com")
    if err == nil {
        t.Error("Expected RequestPasswordReset to return error for non-existent email")
    }
    
    if err.Error() != "user with email 'nonexistent@example.com' not found" {
        t.Errorf("Expected specific error for non-existent email, got: %v", err)
    }
}

// TestUserService_ResetPassword tests password reset
func TestUserService_ResetPassword(t *testing.T) {
    service := NewMockUserService()
    
    // Add a user with reset token for testing
    user := &models.User{
        ID:        3,
        Username:  "resetpwuser",
        Email:     "resetpw@example.com",
        FirstName: "ResetPW",
        LastName:  "User",
        Age:       25,
        ResetToken: "testtoken",
        ResetTokenExpiresAt: time.Now().Add(1 * time.Hour),
    }
    service.users[3] = user
    
    err := service.ResetPassword("testtoken", "newpassword123")
    if err != nil {
        t.Errorf("ResetPassword('testtoken', 'newpassword123') returned error: %v", err)
    }
    
    // Verify token was cleared
    updatedUser, err := service.GetUserByID(3)
    if err != nil {
        t.Errorf("Failed to get user after reset: %v", err)
    }
    
    if updatedUser.ResetToken != "" {
        t.Error("Expected ResetPassword to clear reset token")
    }
    
    if updatedUser.ResetTokenExpiresAt.IsZero() {
        t.Error("Expected ResetPassword to clear expiration time")
    }
    
    // Test with invalid token
    err = service.ResetPassword("invalidtoken", "newpassword")
    if err == nil {
        t.Error("Expected ResetPassword to return error for invalid token")
    }
    
    if err.Error() != "invalid reset token" {
        t.Errorf("Expected specific error for invalid token, got: %v", err)
    }
    
    // Test with expired token
    expiredUser := &models.User{
        ID:        4,
        Username:  "expireduser",
        Email:     "expired@example.com",
        FirstName: "Expired",
        LastName:  "User",
        Age:       25,
        ResetToken: "expiredtoken",
        ResetTokenExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
    }
    service.users[4] = expiredUser
    
    err = service.ResetPassword("expiredtoken", "newpassword")
    if err == nil {
        t.Error("Expected ResetPassword to return error for expired token")
    }
    
    if err.Error() != "reset token has expired" {
        t.Errorf("Expected specific error for expired token, got: %v", err)
    }
}

// TestUserService_ValidateResetToken tests token validation
func TestUserService_ValidateResetToken(t *testing.T) {
    service := NewMockUserService()
    
    // Add a user with valid token
    user := &models.User{
        ID:        5,
        Username:  "validtokenuser",
        Email:     "validtoken@example.com",
        FirstName: "ValidToken",
        LastName:  "User",
        Age:       25,
        ResetToken: "validtoken",
        ResetTokenExpiresAt: time.Now().Add(1 * time.Hour),
    }
    service.users[5] = user
    
    validatedUser, err := service.ValidateResetToken("validtoken")
    if err != nil {
        t.Errorf("ValidateResetToken('validtoken') returned error: %v", err)
    }
    
    if validatedUser.ID != 5 {
        t.Errorf("ValidateResetToken returned wrong user")
    }
    
    // Test with invalid token
    _, err = service.ValidateResetToken("invalidtoken")
    if err == nil {
        t.Error("Expected ValidateResetToken to return error for invalid token")
    }
    
    if err.Error() != "invalid reset token" {
        t.Errorf("Expected specific error for invalid token, got: %v", err)
    }
    
    // Test with expired token
    expiredUser := &models.User{
        ID:        6,
        Username:  "expiredtokenuser",
        Email:     "expiredtoken@example.com",
        FirstName: "ExpiredToken",
        LastName:  "User",
        Age:       25,
        ResetToken: "expiredtoken",
        ResetTokenExpiresAt: time.Now().Add(-1 * time.Hour),
    }
    service.users[6] = expiredUser
    
    _, err = service.ValidateResetToken("expiredtoken")
    if err == nil {
        t.Error("Expected ValidateResetToken to return error for expired token")
    }
    
    if err.Error() != "reset token has expired" {
        t.Errorf("Expected specific error for expired token, got: %v", err)
    }
}


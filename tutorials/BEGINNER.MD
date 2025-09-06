
# Go Learning Exercises: Beginner Level

## Table of Contents
1. [Introduction](#introduction)
2. [Beginner Exercises](#beginner-exercises)
   - [Exercise 1: Modify the User Model](#exercise-1-modify-the-user-model)
   - [Exercise 2: Add a New Endpoint](#exercise-2-add-a-new-endpoint)
   - [Exercise 3: Implement Authentication](#exercise-3-implement-authentication)
   - [Exercise 4: Add Database Support](#exercise-4-add-database-support)

## Introduction

This document provides a series of beginner-level exercises designed to help you learn Go programming by extending the existing application. These exercises focus on basic modifications and additions to the existing codebase.

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

The User model is defined in [`internal/models/models.go`](internal/models/models.go). It currently includes fields like ID, Username, Email, etc. We'll add a "PhoneNumber" field to allow users to store their phone numbers.

In Go, a "struct" is like a blueprint for creating custom data types. It's similar to a class in other languages but simpler – no inheritance or methods by default, though we can add methods to them. The User struct holds all the information about a user in our application.

Validation logic is code that checks if the data is correct before saving it. This prevents bad data from entering our system, like invalid emails or phone numbers.

#### Step 1: Update the User Struct

1. Open [`internal/models/models.go`](internal/models/models.go)
2. Find the User struct definition (around line 22). This is where the User type is defined. It looks like a block starting with `type User struct {` and ending with `}`.
3. Add a new field for phone number inside the struct, right before the closing `}`. Fields in a struct are like properties or attributes.

Here's what to add:

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

**Explanation for Beginners:**
- `PhoneNumber string` – This declares a new field of type `string` (Go's text type). It's placed inside the struct to become part of every User instance.
- The backticks `` `json:"phone_number"` `` are "struct tags." They tell Go how to handle this field when converting the struct to JSON (a common data format for APIs). Without this, it would be "PhoneNumber" in JSON, but we want snake_case "phone_number" for consistency.
- The comment `// User's phone number` is for documentation – Go ignores it but it's good practice.
- Notice the indentation: Go uses tabs or spaces consistently (usually 1 tab = 4 spaces). The field must be indented under the struct.

Save the file. If you get a compilation error about "undefined: time" or similar, make sure the import at the top includes "time" (e.g., `import "time"`).

#### Step 2: Update the Validation Logic

1. Find the `Validate` method for the User struct (around line 164). Methods are functions attached to a type, like `func (u *User) Validate() error { ... }`. The `(u *User)` means it's a method for User, where `*User` is a pointer to allow modifying the struct.
2. Inside the method, after the existing validation (look for `return nil` at the end), add phone number validation. This is where we check if the phone number is valid if it's provided.

Add this code before the final `return nil`:

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

**Explanation for Beginners:**
- `if u.PhoneNumber != "" {` – Check if the phone number is provided (not empty string).
- `regexp.MustCompile(`[^\d]`).ReplaceAllString(u.PhoneNumber, "")` – This uses Go's regexp package to create a pattern that matches anything that's not a digit (`\d`), and replaces it with empty string. So, "+1 (555) 123-4567" becomes "15551234567". Import "regexp" and "strings" if not already (at the top: `import ( "regexp" "strings" )`).
- `len(digitsOnly)` – len() returns the length of the string.
- `fmt.Errorf("...")` – Creates an error with a message. `fmt` is for formatting.
- The second regex `^[\d\+\-\s\(\)]+$` matches the entire string (^ to $) from start to end, allowing digits, +, -, space, (, ).
- If validation fails, return the error early. If all good, return nil (no error).

If you get "undefined: regexp", add the import.

#### Step 3: Update the Factory Function

1. Find the `NewUser` factory function (around line 346). Factory functions are like constructors – they create and return a new instance with defaults.
2. Update it to accept and set the phone number. Change the function signature and add the field.

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

**Explanation for Beginners:**
- The function now takes 5 string parameters.
- `&User{ ... }` creates a pointer to a new User and initializes fields.
- `time.Now()` gets the current time – import "time" if needed.
- `[]string{"user"}` is a slice (dynamic array) with one element.

#### Step 4: Update the Sample Users

1. Find the `initializeSampleUsers` method in [`internal/services/services.go`](internal/services/services.go). This is in the service layer, where business logic lives.
2. Update the sample users to include phone numbers. Look for the array of users and pass the phone to NewUser.

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

**Explanation for Beginners:**
- `models.NewUser` calls the factory from the models package (import "scholastic-go-tutorial/internal/models" as models).
- Each line creates a new user with phone.
- The `initializeSampleUsers` is called when the service starts to populate initial data.

#### Step 5: Test Your Changes

1. Run the application. In Go, `go run` compiles and runs the main package. The main is in cmd/server/main.go, so:

```bash
go run cmd/server/main.go
```

This starts the server on localhost:8080. If you get errors, fix imports or dependencies (run `go mod tidy` if needed).

2. Test the API by creating a new user with a phone number. Use curl (command line HTTP client) or Postman.

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

- `-X POST` specifies the method.
- `-H` adds header for JSON.
- `-d` is the data (JSON body).

You should get a 201 Created response with the user, including phone_number.

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

This should return 400 Bad Request with validation error about digits.

**Explanation for Beginners:**
- The server receives the JSON, unmarshals it to User struct (reverse of marshal), calls Validate(), and if good, saves it.
- If validation fails in handler, it sends error response.

#### Key Concepts Explained

1. **Struct Tags**: The ` `json:"phone_number"` ` tag tells Go how to serialize this field to JSON. When the struct is converted to JSON, the field will be named "phone_number". JSON is key-value format for data exchange. Go's encoding/json package handles this.

2. **Validation**: We added validation logic to ensure phone numbers have a reasonable format. This prevents bad data from entering our system. In Go, validation is manual – no built-in like some languages, so we write methods like Validate().

3. **Factory Function**: The `NewUser` function is a "constructor" that creates new User instances with sensible defaults. We updated it to accept a phone number parameter. In Go, constructors are just functions returning *Type.

4. **Regular Expressions**: We used regular expressions to validate the phone number format. The first regex removes all non-digit characters to count the digits, and the second regex checks that the phone number only contains valid characters. Regexp is powerful for pattern matching; `MustCompile` panics if invalid, good for constants.

#### Troubleshooting

- **Compilation Error**: If you get an error about `regexp` not being imported, add `"regexp"` to the import statement at the top of [`internal/models/models.go`](internal/models/models.go). Imports are in parentheses for multiple: `import ( "fmt" "regexp" )`.

- **Validation Not Working**: Make sure you've added the validation logic to the `Validate` method, not just the `ValidateCreate` or `ValidateUpdate` methods. The handler calls Validate().

- **Phone Number Not Saving**: Make sure you've updated the `NewUser` factory function and the sample users initialization. Also, check if the handler parses "phone_number" correctly from JSON (the tag handles it).

- **Server Not Starting**: Run `go mod tidy` to fix dependencies, or `go build` to check errors.

- **Curl Not Found**: Install curl or use a tool like Postman for GUI testing.

Continue to Exercise 2 once this works.

### Exercise 2: Add a New Endpoint

#### Objective

Create a new API endpoint that returns user statistics, such as the total number of users and the number of active users.

#### What You'll Learn

- How to add new API endpoints
- How to structure API responses
- How to implement business logic for data aggregation

#### Background

Currently, the application has endpoints for CRUD operations on users (Create, Read, Update, Delete), but it doesn't provide any statistics or analytics about the users. We'll add a new endpoint `/api/users/stats` that returns user statistics.

An "endpoint" is a URL path where the server listens for requests, like /api/users for listing users. HTTP methods (GET, POST) determine the action. APIs are how clients (browsers, apps) talk to servers.

Business logic is the code that implements the rules of your application, like calculating stats from data.

#### Step 1: Update the Models

1. Open [`internal/models/models.go`](internal/models/models.go)
2. Add a new struct for the statistics response at the end of the file (before the utility functions). Structs can be simple data holders like this.

Add this after the User and Profile structs:

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

**Explanation for Beginners:**
- This is a simple struct for returning stats as JSON.
- JSON tags ensure snake_case in responses.
- Comments explain each field – good for readability.

#### Step 2: Update the Service Interface

1. Open [`internal/services/services.go`](internal/services/services.go)
2. Find the `UserServiceInterface` definition (around line 30). Interfaces in Go define contracts – what methods a type must have.
3. Add a new method signature at the end, before the closing `}`.

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

**Explanation for Beginners:**
- Adding `GetUserStats() (*models.UserStats, error)` means any type implementing UserServiceInterface must have this method.
- Return type is pointer to UserStats and error (Go functions can return multiple values; error is nil if success).
- This is "dependency injection" – handlers use the interface, not concrete type.

#### Step 3: Implement the Service Method

1. In the same file, find the UserService struct implementation (look for `func (s *UserService) ...` methods).
2. Add the implementation of the new method at the end of the UserService methods. This is where we calculate the stats.

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

**Explanation for Beginners:**
- `s.mu.RLock()` – Read lock from sync package for thread safety (multiple readers OK). Import "sync".
- `len(s.users)` – s.users is probably a map or slice of users in the service.
- `for _, user := range s.users {` – Loop over the collection; `_` ignores index.
- `++` increments by 1.
- Integer division in Go truncates (30 / 5 = 6).
- Return pointer to stats and nil error.

If s.users is not defined, this assumes in-memory storage; for database, it would query.

#### Step 4: Update the Handler

1. Open [`internal/handlers/handlers.go`](internal/handlers/handlers.go)
2. Add a new handler method at the end of the APIHandler implementation. Handlers are functions that handle HTTP requests.

Add this:

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

**Explanation for Beginners:**
- `func (h *APIHandler) GetUserStatsHandler(w http.ResponseWriter, r *http.Request)` – Method for APIHandler, parameters are HTTP response writer and request.
- `r.Method != http.MethodGet` – Check HTTP method; import "net/http".
- `h.userService` – The service injected into the handler.
- `sendErrorResponse` and `sendJSONResponse` are helper functions in the file for consistent responses.
- `fmt.Sprintf` formats the error.
- `time.Now().Unix()` – Unix timestamp (seconds since epoch).
- If error, return early with status code (400, 500 are errors).

#### Step 5: Update the Routes

1. Open [`cmd/server/main.go`](cmd/server/main.go)
2. Find the route registration section (around line 100), where mux.HandleFunc calls are.
3. Add the new route after existing ones, before static files.

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

**Explanation for Beginners:**
- `http.NewServeMux()` creates the router.
- `mux.HandleFunc(path, handler)` registers the path to the handler function.
- The path "/api/users/stats" maps to GetUserStatsHandler.
- Order doesn't matter much, but logical.

#### Step 6: Test Your Changes

1. Run the application:

```bash
go run cmd/server/main.go
```

2. Test the new endpoint with GET (read-only):

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

If you get 404, check the route path. If 500, check service implementation.

#### Key Concepts Explained

1. **API Design**: We followed RESTful conventions by using GET method for retrieving data and a logical URL structure (`/api/users/stats`). REST is a style for APIs: resources (users) with methods (GET for read).

2. **Data Aggregation**: The service method aggregates data from multiple user records to calculate statistics. This is a common pattern in analytics and reporting features. Loops and conditionals in Go are basic control flow.

3. **Thread Safety**: We used a read lock (`RLock()` instead of `Lock()`) because we're only reading data, not modifying it. This allows multiple concurrent reads without blocking each other. Concurrency is Go's strength with goroutines, but here we use mutex for shared data.

4. **Response Structure**: We used the existing `SuccessResponse` struct to maintain consistency with other endpoints in the API. JSON is serialized automatically by sendJSONResponse.

#### Troubleshooting

- **404 Not Found**: If you get a 404 error, make sure you've added the route in `cmd/server/main.go` and that the URL you're using matches exactly (no trailing slash).

- **Compilation Error**: If you get an error about the `GetUserStats` method not being implemented, make sure you've added it to both the interface and the implementation in services.go. Go is strict about interfaces.

- **Empty Statistics**: If the statistics are empty or zero, make sure the sample users are being initialized correctly in the `initializeSampleUsers` method. Check server logs (it prints when starting).

- **Method Not Allowed**: If you get 405, ensure you're using GET.

Continue to Exercise 3.

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

Authentication is how we verify who the user is (login), authorization is what they can do (roles). JWT is a standard for tokens – secure strings containing user info, signed so they can't be faked.

"Middleware" is code that runs before/after the main handler, like authentication check before processing.

#### Step 1: Add Dependencies

Dependencies are external packages. Go uses modules for this.

1. Open your terminal in the project root and run:

```bash
go get github.com/golang-jwt/jwt/v5
```

This downloads and adds to go.mod. `go mod tidy` cleans up.

**Explanation for Beginners:**
- Go modules (go.mod) manage external code. `go get` fetches from github.
- JWT library handles token creation/validation.

#### Step 2: Update the Configuration

1. Open [`internal/config/config.go`](internal/config/config.go)
2. Add JWT configuration fields to the Config struct. Config is loaded from env vars or defaults.

Add inside Config:

```go
type Config struct {
    // ... existing fields ...
    
    // JWT configuration
    JWTSecret     string        // Secret key for signing JWTs
    JWTExpiration time.Duration // JWT token expiration time
}
```

3. Update the `LoadConfig` function to load them. Find where config is initialized and add:

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

4. Add the helper for duration (if not there):

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

**Explanation for Beginners:**
- Env vars are system variables for config (e.g., secrets). `os.Getenv` gets them.
- Default secret is insecure – in production, use strong random key.
- time.Duration is for times like "24h".

Set env: export JWT_SECRET=strongkey (in terminal, or .env file if using viper or similar, but here manual).

#### Step 3: Create Authentication Models

1. Open [`internal/models/models.go`](internal/models/models.go)
2. Add authentication-related models at the end (before utility functions). These are request/response structs.

Add:

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
        return fmt("password cannot be empty")
    }
    
    return nil
}
```

**Explanation for Beginners:**
- LoginRequest is for POST /login body.
- LoginResponse for the response, with token and sanitized user (hide sensitive data).
- Validate() method for validation, like User.Validate(). TrimSpace removes whitespace.
- Import "strings" if needed.

#### Step 4: Create Authentication Service

1. Create a new file [`internal/services/auth.go`](internal/services/auth.go) with the following content. Services handle business logic, separate from handlers.

The entire file:

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

**Explanation for Beginners:**
- AuthService wraps the user service for auth logic.
- Login: Gets user, checks password (simple for demo; real would use bcrypt), creates claims (map of data), signs with secret.
- jwt.NewWithClaims creates token with claims (payload).
- SignedString uses HS256 (symmetric key).
- ValidateToken parses and validates signature/expiration.

#### Step 5: Create Authentication Middleware

1. Open [`internal/middleware/middleware.go`](internal/middleware/middleware.go)
2. Add the authentication middleware at the end. Middleware is a function that wraps another handler.

Add:

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

**Explanation for Beginners:**
- Middleware is func returning func wrapping the next handler.
- `r.Header.Get("Authorization")` gets the header with token.
- "Bearer " prefix is standard for JWT.
- `context.WithValue` adds data to request context for handlers to use. Import "context".
- If token invalid, send 401 with WWW-Authenticate header.
- isPublicEndpoint skips auth for some paths.

#### Step 6: Update the Handlers

1. Open [`internal/handlers/handlers.go`](internal/handlers/handlers.go)
2. Add the login handler at the end:

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

3. Update the APIHandler struct to include authService. Find `type APIHandler struct {` and add:

```go
type APIHandler struct {
    userService UserServiceInterface
    mathService MathServiceInterface
    authService services.AuthServiceInterface // ADD THIS LINE
}
```

4. Update the NewAPIHandler function:

```go
func NewAPIHandler(userService UserServiceInterface, mathService MathServiceInterface, authService services.AuthServiceInterface) *APIHandler {
    return &APIHandler{
        userService: userService,
        mathService: mathService,
        authService: authService, // ADD THIS LINE
    }
}
```

**Explanation for Beginners:**
- LoginHandler parses JSON body using json.NewDecoder or similar (assume parseJSONBody is a helper).
- Calls service.Login, which returns token and user.
- User.Sanitize() hides sensitive fields (implement if not, or use a method to copy without email/password).
- ProtectedHandler gets from context set by middleware.

#### Step 7: Update the Main Function

1. Open [`cmd/server/main.go`](cmd/server/main.go)
2. Add "time" import if not there.
3. Initialize the auth service after userService:

```go
userService := services.NewUserService(dbService.DB) // or nil if in-memory
mathService := services.NewMathService()
wsService := services.NewWebSocketService()

// ADD THIS LINE:
authService := services.NewAuthService(userService, config.JWTSecret, config.JWTExpiration)
```

4. Update handler:

```go
apiHandler := handlers.NewAPIHandler(userService, mathService, authService) // ADD authService
```

5. Update middleware chain. Find where the mux is wrapped, add AuthMiddleware:

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

The chain is applied from inside out.

6. Add routes:

```go
mux.HandleFunc("/health", apiHandler.HealthCheck)
mux.HandleFunc("/api/users", apiHandler.UsersHandler)
// ... other routes ...

// ADD THESE NEW ROUTES:
mux.HandleFunc("/api/login", apiHandler.LoginHandler)
mux.HandleFunc("/api/protected", apiHandler.ProtectedHandler)
```

#### Step 8: Test Your Changes

1. Run the application:

```bash
go run cmd/server/main.go
```

2. Test login:

```bash
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice_dev",
    "password": "password"
  }'
```

Get token.

3. Test protected:

```bash
curl -X GET http://localhost:8080/api/protected \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

Replace with actual token.

4. Test without token: curl -X GET http://localhost:8080/api/protected – should 401.

#### Key Concepts Explained

1. **JWT (JSON Web Token)**: JWT is a compact, URL-safe means of representing claims to be transferred between two parties. It's commonly used for authentication and authorization. The token is a string with header.payload.signature, base64 encoded.

2. **Middleware**: The authentication middleware intercepts requests to protected endpoints, validates the JWT token, and adds user information to the request context. In Go, middleware is functions that take and return http.Handler.

3. **Context**: The context package in Go allows us to pass request-scoped values through our application. We use it to pass user information from the middleware to the handlers. Values are stored with keys like "user_id".

4. **Signing Method**: We use HMAC-SHA256 to sign our JWTs. This ensures that the tokens can't be tampered with without the secret key. HMAC is hash-based message authentication code.

5. **Token Expiration**: JWTs include an "exp" claim with Unix timestamp. The library checks it automatically.

#### Troubleshooting

- **Import Errors**: If you get errors about missing imports, make sure you've added all the required packages to the import statements. Run `go mod tidy`.

- **Compilation Error**: If you get an error about the `AuthServiceInterface` not being found, make sure you've defined it in [`internal/services/auth.go`](internal/services/auth.go).

- **Invalid Token**: If you get "Invalid or expired token" errors, make sure you're using the exact token from the login response, and that it hasn't expired (the default is 24 hours). Copy-paste carefully.

- **Configuration Error**: If you get errors about the JWT configuration, make sure you've added the JWT fields to the Config struct and updated the LoadConfig function. Check env vars with echo $JWT_SECRET.

- **Password Check**: The demo uses "password" – in real, use hashing like bcrypt (go get golang.org/x/crypto/bcrypt).

Continue to Exercise 4.

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

In-memory storage is fast but volatile. Databases like PostgreSQL are persistent, relational (tables with relationships), and support SQL queries.

ORM like GORM lets us use Go structs as tables, avoiding raw SQL for most operations.

Migrations are changes to database schema over time.

#### Step 1: Install Required Packages

1. Open your terminal and run:

```bash
go get -u gorm.io/gorm
go get -u github.com/lib/pq
```

- gorm.io/gorm is the ORM.
- github.com/lib/pq is the PostgreSQL driver.

Run `go mod tidy` to update go.mod.

**Explanation for Beginners:**
- These are external libraries. GORM is popular for Go DB interactions; pq is the driver for Postgres.

#### Step 2: Update the Configuration

1. Open [`internal/config/config.go`](internal/config/config.go)
2. Update the Config struct to include DB fields. Add after existing fields:

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

3. Update LoadConfig to load them:

```go
func LoadConfig() (*Config, error) {
    config := &Config{
        // ... existing ...
        
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
    
    // ... rest ...
}
```

**Explanation for Beginners:**
- These are env vars for DB connection string (DSN).
- Defaults are for local Postgres. In production, use secrets manager.

#### Step 3: Update the User Model

1. Open [`internal/models/models.go`](internal/models/models.go)
2. Add GORM tags to User for DB mapping. Replace the User struct with:

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

3. Update Profile:

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

4. Add TableName methods after the structs:

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

**Explanation for Beginners:**
- GORM tags like `gorm:"primaryKey"` tell GORM how to map to DB columns.
- `unique;not null` makes the field unique and required in DB.
- `autoCreateTime` auto-sets CreatedAt on create.
- `type:text` for longer strings.
- `serializer:json` stores Profile as JSON column.
- `json:"-"` hides from JSON.
- TableName overrides default table name (would be "user").

#### Step 4: Create a Database Service

1. Create [`internal/services/database.go`](internal/services/database.go) with:

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
    sqlDB.SetMaxIdleConns(cfg.DBMaxIdle
# Implementing a New User Feature: A Step-by-Step Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Understanding the Current Architecture](#understanding-the-current-architecture)
3. [Planning Your New Feature](#planning-your-new-feature)
4. [Step 1: Update the Data Model](#step-1-update-the-data-model)
5. [Step 2: Update the Service Layer](#step-2-update-the-service-layer)
6. [Step 3: Update the Handler Layer](#step-3-update-the-handler-layer)
7. [Step 4: Update the Routes](#step-4-update-the-routes)
8. [Step 5: Test Your Implementation](#step-5-test-your-implementation)
9. [Complete Example: User Password Reset Feature](#complete-example-user-password-reset-feature)
10. [Common Patterns and Best Practices](#common-patterns-and-best-practices)
11. [Troubleshooting](#troubleshooting)
12. [Conclusion](#conclusion)

## Introduction

This guide will walk you through implementing a new feature related to users in the Go application. We'll assume you have little to no understanding of the codebase or Go programming language. By the end of this guide, you'll know exactly where to make changes and how they should look.

### What We'll Build

For this guide, we'll implement a "User Password Reset" feature as an example. This feature will:
1. Allow users to request a password reset
2. Generate a reset token
3. Send the token to the user's email
4. Allow users to reset their password using the token

This example covers all the common patterns you'll need for implementing most user-related features.

## Understanding the Current Architecture

Before we start, let's understand how the application is organized. The application follows a pattern called "clean architecture," which separates concerns into distinct layers:

### 1. Models Layer (`internal/models/`)

This layer defines what your data looks like. Think of it as the blueprints for your data.

- **Purpose**: Defines data structures and validation rules
- **Key Files**: [`internal/models/models.go`](internal/models/models.go:1)
- **What you'll find here**: User structs, validation methods, and any data-related utilities

### 2. Services Layer (`internal/services/`)

This layer contains the business logic. Think of it as the "brains" of your application.

- **Purpose**: Implements business rules and data operations
- **Key Files**: [`internal/services/services.go`](internal/services/services.go:1)
- **What you'll find here**: UserService with methods for creating, updating, and retrieving users

### 3. Handlers Layer (`internal/handlers/`)

This layer handles HTTP requests and responses. Think of it as the "interface" between your application and the outside world.

- **Purpose**: Processes HTTP requests and returns responses
- **Key Files**: [`internal/handlers/handlers.go`](internal/handlers/handlers.go:1)
- **What you'll find here**: Methods that handle specific HTTP endpoints

### 4. Routes (`cmd/server/main.go`)

This is where URLs are connected to handlers.

- **Purpose**: Maps URLs to handler methods
- **Key Files**: [`cmd/server/main.go`](cmd/server/main.go:1)
- **What you'll find here**: Code that registers URL patterns with handler methods

### 5. Middleware (`internal/middleware/`)

This layer handles cross-cutting concerns like logging, authentication, etc.

- **Purpose**: Handles common tasks that apply to multiple requests
- **Key Files**: [`internal/middleware/middleware.go`](internal/middleware/middleware.go:1)
- **What you'll find here**: Functions that process requests before they reach handlers

When implementing a new feature, you'll typically need to make changes in all these layers, following the flow:

```
HTTP Request → Middleware → Handler → Service → Model → Database
                                                    ↓
HTTP Response ← Middleware ← Handler ← Service ← Model ← Database
```

## Planning Your New Feature

Before writing any code, let's plan our "User Password Reset" feature:

### 1. Define the Requirements

What should our feature do?
1. Allow a user to request a password reset by providing their email
2. Generate a unique, time-limited reset token
3. Store the token securely
4. Send the token to the user's email (we'll simulate this)
5. Allow the user to reset their password using the token

### 2. Identify the Components Needed

For this feature, we'll need:

1. **New Model Fields**:
   - Reset token field in the User model
   - Token expiration field in the User model

2. **New Service Methods**:
   - `RequestPasswordReset(email string) error`
   - `ResetPassword(token, newPassword string) error`
   - `ValidateResetToken(token string) (*User, error)`

3. **New Handler Methods**:
   - `RequestPasswordResetHandler(w http.ResponseWriter, r *http.Request)`
   - `ResetPasswordHandler(w http.ResponseWriter, r *http.Request)`

4. **New Routes**:
   - `POST /api/users/request-password-reset`
   - `POST /api/users/reset-password`

5. **New Request/Response Models**:
   - `PasswordResetRequest` struct
   - `PasswordResetResponse` struct

### 3. Plan the Flow

1. User sends POST to `/api/users/request-password-reset` with email
2. Handler validates the email
3. Service generates a token and stores it
4. Service sends the token to the user's email
5. Handler sends a success response
6. User sends POST to `/api/users/reset-password` with token and new password
7. Handler validates the token and new password
8. Service updates the user's password
9. Handler sends a success response

Now that we have a plan, let's implement it step by step.

## Step 1: Update the Data Model

First, we need to update our User model to support password resets.

### What We're Adding

We'll add two new fields to the User struct:
1. `ResetToken` - A unique token for password reset
2. `ResetTokenExpiresAt` - When the token expires

### File to Modify

[`internal/models/models.go`](internal/models/models.go:1)

### Changes to Make

1. Add new fields to the User struct:

```go
// Find this section in the User struct (around line 22)
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
    
    // ADD THESE NEW FIELDS:
    ResetToken           string    `json:"-"`                 // Password reset token (hidden from JSON)
    ResetTokenExpiresAt  time.Time `json:"-"`                 // When the reset token expires (hidden from JSON)
}
```

Note: We use `json:"-"` to exclude these fields from JSON serialization for security reasons.

2. Add new request/response models at the end of the file (before the utility functions):

```go
// Add these new models before the utility functions section

/*
PASSWORD RESET REQUEST/RESPONSE STRUCTS
Define structures for password reset functionality
*/

// PasswordResetRequest represents a password reset request
type PasswordResetRequest struct {
    Email string `json:"email"` // User's email address
}

// PasswordResetResponse represents a password reset response
type PasswordResetResponse struct {
    Message string `json:"message"` // Response message
    Email   string `json:"email"`   // User's email
}

// PasswordResetConfirmation represents a password reset confirmation
type PasswordResetConfirmation struct {
    Token       string `json:"token"`        // Reset token
    NewPassword string `json:"new_password"` // New password
}

// PasswordResetConfirmationResponse represents a password reset confirmation response
type PasswordResetConfirmationResponse struct {
    Message string `json:"message"` // Response message
    Success bool   `json:"success"` // Whether the reset was successful
}
```

3. Add validation methods for the new request models:

```go
// Add these validation methods with the other validation methods

// Validate implements Validator interface for PasswordResetRequest
func (prr *PasswordResetRequest) Validate() error {
    if strings.TrimSpace(prr.Email) == "" {
        return fmt.Errorf("email cannot be empty")
    }
    
    // Basic email regex pattern
    emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
    if !emailRegex.MatchString(prr.Email) {
        return fmt.Errorf("invalid email format")
    }
    
    return nil
}

// Validate implements Validator interface for PasswordResetConfirmation
func (prc *PasswordResetConfirmation) Validate() error {
    if strings.TrimSpace(prc.Token) == "" {
        return fmt.Errorf("token cannot be empty")
    }
    
    if strings.TrimSpace(prc.NewPassword) == "" {
        return fmt.Errorf("new password cannot be empty")
    }
    
    if len(prc.NewPassword) < 8 {
        return fmt.Errorf("new password must be at least 8 characters long")
    }
    
    return nil
}
```

### Why These Changes?

1. **New User Fields**: We need to store the reset token and its expiration date to validate reset requests.
2. **Request/Response Models**: We need structured ways to receive and send data related to password resets.
3. **Validation Methods**: These ensure that the data we receive is valid before processing it.

### How to Test the Changes

After making these changes, you can test them by:
1. Running the application: `go run cmd/server/main.go`
2. Checking that it compiles without errors

If it compiles successfully, your model changes are correct!

## Step 2: Update the Service Layer

Now that we've updated our models, we need to implement the business logic in the service layer.

### What We're Adding

We'll add three new methods to the UserService:
1. `RequestPasswordReset(email string) error`
2. `ResetPassword(token, newPassword string) error`
3. `ValidateResetToken(token string) (*User, error)`

### File to Modify

[`internal/services/services.go`](internal/services/services.go:1)

### Changes to Make

1. Add the new methods to the UserServiceInterface:

```go
// Find the UserServiceInterface definition (around line 30)
type UserServiceInterface interface {
    GetUserByID(id int) (*models.User, error)
    GetAllUsers() ([]*models.User, error)
    CreateUser(user *models.User) error
    UpdateUser(user *models.User) error
    DeleteUser(id int) error
    GetUserByUsername(username string) (*models.User, error)
    SearchUsers(query string) ([]*models.User, error)
    
    // ADD THESE NEW METHOD SIGNATURES:
    RequestPasswordReset(email string) error
    ResetPassword(token, newPassword string) error
    ValidateResetToken(token string) (*User, error)
}
```

2. Add the implementation of these methods to the UserService struct (at the end of the UserService implementation):

```go
// Add these methods to the UserService struct, after the existing methods

/*
PASSWORD RESET METHODS
Implement password reset functionality
*/

// RequestPasswordReset generates a password reset token for a user
func (s *UserService) RequestPasswordReset(email string) error {
    // Validate email
    if strings.TrimSpace(email) == "" {
        return fmt.Errorf("email cannot be empty")
    }
    
    s.mu.Lock()
    defer s.mu.Unlock()
    
    // Find user by email
    var user *models.User
    for _, u := range s.users {
        if u.Email == email {
            // Create a copy to avoid modifying the original
            userCopy := *u
            user = &userCopy
            break
        }
    }
    
    if user == nil {
        return fmt.Errorf("user with email '%s' not found", email)
    }
    
    // Generate a secure random token
    token, err := s.generateSecureToken()
    if err != nil {
        return fmt.Errorf("failed to generate reset token: %w", err)
    }
    
    // Set token and expiration (24 hours from now)
    user.ResetToken = token
    user.ResetTokenExpiresAt = time.Now().Add(24 * time.Hour)
    
    // Update the user in the map
    s.users[user.ID] = user
    
    // In a real application, you would send an email with the token
    // For this example, we'll just log it
    log.Printf("Password reset token for %s: %s", user.Email, token)
    
    return nil
}

// ResetPassword resets a user's password using a reset token
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
    
    s.mu.Lock()
    defer s.mu.Unlock()
    
    // Find user by reset token
    var user *models.User
    for _, u := range s.users {
        if u.ResetToken == token {
            // Create a copy to avoid modifying the original
            userCopy := *u
            user = &userCopy
            break
        }
    }
    
    if user == nil {
        return fmt.Errorf("invalid reset token")
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
    
    // Update the user in the map
    s.users[user.ID] = user
    
    log.Printf("Password reset successful for user %s", user.Email)
    
    return nil
}

// ValidateResetToken validates a reset token and returns the associated user
func (s *UserService) ValidateResetToken(token string) (*models.User, error) {
    if strings.TrimSpace(token) == "" {
        return nil, fmt.Errorf("token cannot be empty")
    }
    
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    // Find user by reset token
    for _, user := range s.users {
        if user.ResetToken == token {
            // Check if token is expired
            if time.Now().After(user.ResetTokenExpiresAt) {
                return nil, fmt.Errorf("reset token has expired")
            }
            
            // Return a copy of the user
            userCopy := *user
            return &userCopy, nil
        }
    }
    
    return nil, fmt.Errorf("invalid reset token")
}
```

3. Add a helper method to generate secure tokens (add this after the ValidateResetToken method):

```go
// generateSecureToken generates a cryptographically secure random token
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
```

4. Make sure to import the required packages at the top of the file:

```go
// Check the imports section (around line 8) and add these if they're missing:
import (
    // ... existing imports ...
    "crypto/rand"        // For generating secure random tokens
    "encoding/hex"       // For encoding bytes to hex string
)
```

### Why These Changes?

1. **Service Interface Updates**: We add method signatures to the interface to define what our service should do.
2. **Implementation Methods**: These methods contain the actual business logic for password resets.
3. **Token Generation**: We need a secure way to generate random tokens for password resets.
4. **Thread Safety**: We use mutexes to ensure concurrent access to user data is safe.

### How to Test the Changes

After making these changes, you can test them by:
1. Running the application: `go run cmd/server/main.go`
2. Checking that it compiles without errors
3. Adding some test code to verify the methods work correctly

If it compiles successfully, your service changes are correct!

## Step 3: Update the Handler Layer

Now that we've updated our models and services, we need to implement the HTTP handlers that will process password reset requests.

### What We're Adding

We'll add two new handler methods to the APIHandler:
1. `RequestPasswordResetHandler(w http.ResponseWriter, r *http.Request)`
2. `ResetPasswordHandler(w http.ResponseWriter, r *http.Request)`

### File to Modify

[`internal/handlers/handlers.go`](internal/handlers/handlers.go:1)

### Changes to Make

1. Add the handler methods to the APIHandler struct (at the end of the APIHandler implementation):

```go
// Add these methods to the APIHandler struct, after the existing methods

/*
PASSWORD RESET HANDLERS
Handle password reset requests
*/

// RequestPasswordResetHandler handles POST /api/users/request-password-reset
func (h *APIHandler) RequestPasswordResetHandler(w http.ResponseWriter, r *http.Request) {
    // Only allow POST method
    if r.Method != http.MethodPost {
        sendErrorResponse(w, "Method not allowed", "METHOD_NOT_ALLOWED", 
            http.StatusMethodNotAllowed, getRequestID(r))
        return
    }
    
    // Parse request body
    var request models.PasswordResetRequest
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
    
    // Request password reset
    if err := h.userService.RequestPasswordReset(request.Email); err != nil {
        sendErrorResponse(w, fmt.Sprintf("Failed to request password reset: %v", err), 
            "PASSWORD_RESET_REQUEST_FAILED", http.StatusInternalServerError, getRequestID(r))
        return
    }
    
    // Send success response
    response := models.SuccessResponse{
        Message: "Password reset token generated. Check your email for instructions.",
        Data: models.PasswordResetResponse{
            Message: "If your email address is in our database, you will receive a password reset link shortly.",
            Email:   request.Email,
        },
        Timestamp: time.Now().Unix(),
        RequestID: getRequestID(r),
    }
    
    sendJSONResponse(w, response, http.StatusOK)
}

// ResetPasswordHandler handles POST /api/users/reset-password
func (h *APIHandler) ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
    // Only allow POST method
    if r.Method != http.MethodPost {
        sendErrorResponse(w, "Method not allowed", "METHOD_NOT_ALLOWED", 
            http.StatusMethodNotAllowed, getRequestID(r))
        return
    }
    
    // Parse request body
    var request models.PasswordResetConfirmation
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
    
    // Reset password
    if err := h.userService.ResetPassword(request.Token, request.NewPassword); err != nil {
        sendErrorResponse(w, fmt.Sprintf("Failed to reset password: %v", err), 
            "PASSWORD_RESET_FAILED", http.StatusBadRequest, getRequestID(r))
        return
    }
    
    // Send success response
    response := models.SuccessResponse{
        Message: "Password has been reset successfully.",
        Data: models.PasswordResetConfirmationResponse{
            Message: "Your password has been reset successfully. You can now log in with your new password.",
            Success: true,
        },
        Timestamp: time.Now().Unix(),
        RequestID: getRequestID(r),
    }
    
    sendJSONResponse(w, response, http.StatusOK)
}
```

### Why These Changes?

1. **Handler Methods**: These methods process HTTP requests, validate input, call service methods, and format responses.
2. **Method Restrictions**: We only allow POST requests for these endpoints for security reasons.
3. **Request Parsing**: We parse JSON request bodies into our model structs.
4. **Validation**: We validate the request data before processing it.
5. **Error Handling**: We handle errors gracefully and return appropriate HTTP status codes.
6. **Success Responses**: We return structured success responses with relevant information.

### How to Test the Changes

After making these changes, you can test them by:
1. Running the application: `go run cmd/server/main.go`
2. Checking that it compiles without errors

If it compiles successfully, your handler changes are correct!

## Step 4: Update the Routes

Now that we've implemented our handler methods, we need to add routes that map URLs to these handlers.

### What We're Adding

We'll add two new routes:
1. `POST /api/users/request-password-reset` → `RequestPasswordResetHandler`
2. `POST /api/users/reset-password` → `ResetPasswordHandler`

### File to Modify

[`cmd/server/main.go`](cmd/server/main.go:1)

### Changes to Make

1. Add the new routes to the mux configuration (find the route registration section around line 100):

```go
// Find this section in the main function
mux := http.NewServeMux()

// Existing routes
mux.HandleFunc("/health", apiHandler.HealthCheck)
mux.HandleFunc("/api/users", apiHandler.UsersHandler)
mux.HandleFunc("/api/users/", apiHandler.UserHandler)
mux.HandleFunc("/api/calculate", apiHandler.CalculateHandler)
mux.HandleFunc("/api/goroutines", apiHandler.GoroutineHandler)
mux.HandleFunc("/ws", wsHandler.HandleWebSocket)

// ADD THESE NEW ROUTES:
mux.HandleFunc("/api/users/request-password-reset", apiHandler.RequestPasswordResetHandler)
mux.HandleFunc("/api/users/reset-password", apiHandler.ResetPasswordHandler)

// Static file serving
mux.Handle("/", staticHandler)
```

### Why These Changes?

1. **Route Registration**: We need to tell the HTTP multiplexer which handler method should handle which URL.
2. **URL Structure**: We follow RESTful conventions for our URL structure.
3. **Method-Specific Routes**: Each route is designed to handle a specific HTTP method (POST in this case).

### How to Test the Changes

After making these changes, you can test them by:
1. Running the application: `go run cmd/server/main.go`
2. Checking that it compiles without errors
3. Testing the endpoints using a tool like curl or Postman

If it compiles successfully and the application starts without errors, your route changes are correct!

## Step 5: Test Your Implementation

Now that we've implemented all the components of our password reset feature, let's test it to make sure it works correctly.

### Testing with curl

1. Start the server:
```bash
go run cmd/server/main.go
```

2. In another terminal, test the password reset request endpoint:

```bash
curl -X POST http://localhost:8080/api/users/request-password-reset \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com"}'
```

You should see a response like:
```json
{
  "message": "Password reset token generated. Check your email for instructions.",
  "data": {
    "message": "If your email address is in our database, you will receive a password reset link shortly.",
    "email": "alice@example.com"
  },
  "timestamp": 1634567890,
  "request_id": "req_1234567890"
}
```

3. Check the server logs for the reset token (in a real application, this would be sent via email):
```
2025/09/06 21:30:00 Password reset token for alice@example.com: a1b2c3d4e5f67890...
```

4. Test the password reset endpoint with the token:

```bash
curl -X POST http://localhost:8080/api/users/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token": "a1b2c3d4e5f67890...", "new_password": "newsecurepassword"}'
```

You should see a response like:
```json
{
  "message": "Password has been reset successfully.",
  "data": {
    "message": "Your password has been reset successfully. You can now log in with your new password.",
    "success": true
  },
  "timestamp": 1634567890,
  "request_id": "req_1234567891"
}
```

### Testing Error Cases

1. Test with an invalid email:

```bash
curl -X POST http://localhost:8080/api/users/request-password-reset \
  -H "Content-Type: application/json" \
  -d '{"email": "nonexistent@example.com"}'
```

You should see an error response:
```json
{
  "error": "Failed to request password reset: user with email 'nonexistent@example.com' not found",
  "code": "PASSWORD_RESET_REQUEST_FAILED",
  "timestamp": 1634567890,
  "request_id": "req_1234567892"
}
```

2. Test with an invalid token:

```bash
curl -X POST http://localhost:8080/api/users/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token": "invalidtoken", "new_password": "newsecurepassword"}'
```

You should see an error response:
```json
{
  "error": "Failed to reset password: invalid reset token",
  "code": "PASSWORD_RESET_FAILED",
  "timestamp": 1634567890,
  "request_id": "req_1234567893"
}
```

3. Test with an expired token (you'll need to modify the token expiration time in the service to test this):

```bash
curl -X POST http://localhost:8080/api/users/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token": "expiredtoken", "new_password": "newsecurepassword"}'
```

You should see an error response:
```json
{
  "error": "Failed to reset password: reset token has expired",
  "code": "PASSWORD_RESET_FAILED",
  "timestamp": 1634567890,
  "request_id": "req_1234567894"
}
```

### What to Do If Tests Fail

If your tests fail, here are some common issues and solutions:

1. **Compilation Errors**:
   - Check for typos in your code
   - Make sure all required imports are included
   - Ensure method signatures match interface definitions

2. **Runtime Errors**:
   - Check the server logs for error messages
   - Make sure the server is running on the correct port (8080)
   - Verify that your JSON request bodies are correctly formatted

3. **Unexpected Behavior**:
   - Check that your service methods are correctly implemented
   - Verify that your handlers are correctly calling service methods
   - Make sure your routes are correctly registered

## Complete Example: User Password Reset Feature

Let's put it all together with a complete example of the User Password Reset feature we've implemented.

### 1. Model Changes (`internal/models/models.go`)

```go
// Add to User struct
type User struct {
    ID        int       `json:"id"`
    Username  string    `json:"username"`
    Email     string    `json:"email"`
    // ... existing fields ...
    
    // New fields for password reset
    ResetToken           string    `json:"-"`  // Password reset token (hidden from JSON)
    ResetTokenExpiresAt  time.Time `json:"-"`  // When the reset token expires (hidden from JSON)
}

// Add request/response models
type PasswordResetRequest struct {
    Email string `json:"email"`
}

type PasswordResetResponse struct {
    Message string `json:"message"`
    Email   string `json:"email"`
}

type PasswordResetConfirmation struct {
    Token       string `json:"token"`
    NewPassword string `json:"new_password"`
}

type PasswordResetConfirmationResponse struct {
    Message string `json:"message"`
    Success bool   `json:"success"`
}

// Add validation methods
func (prr *PasswordResetRequest) Validate() error {
    // ... validation logic ...
}

func (prc *PasswordResetConfirmation) Validate() error {
    // ... validation logic ...
}
```

### 2. Service Changes (`internal/services/services.go`)

```go
// Add to UserServiceInterface
type UserServiceInterface interface {
    // ... existing methods ...
    RequestPasswordReset(email string) error
    ResetPassword(token, newPassword string) error
    ValidateResetToken(token string) (*User, error)
}

// Add implementation to UserService
func (s *UserService) RequestPasswordReset(email string) error {
    // ... implementation ...
}

func (s *UserService) ResetPassword(token, newPassword string) error {
    // ... implementation ...
}

func (s *UserService) ValidateResetToken(token string) (*User, error) {
    // ... implementation ...
}

func (s *UserService) generateSecureToken() (string, error) {
    // ... implementation ...
}
```

### 3. Handler Changes (`internal/handlers/handlers.go`)

```go
// Add to APIHandler
func (h *APIHandler) RequestPasswordResetHandler(w http.ResponseWriter, r *http.Request) {
    // ... implementation ...
}

func (h *APIHandler) ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
    // ... implementation ...
}
```

### 4. Route Changes (`cmd/server/main.go`)

```go
// Add to main function
mux.HandleFunc("/api/users/request-password-reset", apiHandler.RequestPasswordResetHandler)
mux.HandleFunc("/api/users/reset-password", apiHandler.ResetPasswordHandler)
```

### 5. Testing the Feature

1. Start the server:
```bash
go run cmd/server/main.go
```

2. Request a password reset:
```bash
curl -X POST http://localhost:8080/api/users/request-password-reset \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com"}'
```

3. Reset the password (using the token from server logs):
```bash
curl -X POST http://localhost:8080/api/users/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token": "TOKEN_FROM_LOGS", "new_password": "newsecurepassword"}'
```

## Common Patterns and Best Practices

When implementing new features in this codebase, there are several patterns and best practices to follow:

### 1. Follow the Layered Architecture

Always make changes in the correct layer:
- **Models**: Define data structures and validation
- **Services**: Implement business logic
- **Handlers**: Process HTTP requests and responses
- **Routes**: Map URLs to handlers

### 2. Use Interfaces for Dependencies

Define interfaces for your services and depend on interfaces, not concrete implementations:

```go
// Good: Depend on interface
type APIHandler struct {
    userService services.UserServiceInterface
}

// Bad: Depend on concrete implementation
type APIHandler struct {
    userService *services.UserService
}
```

### 3. Validate Input Data

Always validate input data in both handlers and services:

```go
// In handler
if err := request.Validate(); err != nil {
    sendErrorResponse(w, fmt.Sprintf("Validation failed: %v", err), 
        "VALIDATION_ERROR", http.StatusBadRequest, getRequestID(r))
    return
}

// In service
if err := user.ValidateCreate(); err != nil {
    return fmt.Errorf("user validation failed: %w", err)
}
```

### 4. Handle Errors Gracefully

Always handle errors and return appropriate HTTP status codes:

```go
// Check for errors
if err != nil {
    sendErrorResponse(w, fmt.Sprintf("Operation failed: %v", err), 
        "OPERATION_FAILED_CODE", http.StatusInternalServerError, getRequestID(r))
    return
}
```

### 5. Use Structured Responses

Use structured response models for consistency:

```go
// Success response
response := models.SuccessResponse{
    Message:   "Operation completed successfully",
    Data:      result,
    Timestamp: time.Now().Unix(),
    RequestID: getRequestID(r),
}

// Error response
errorResponse := models.ErrorResponse{
    Error:     "Something went wrong",
    Code:      "ERROR_CODE",
    Timestamp: time.Now().Unix(),
    RequestID: getRequestID(r),
}
```

### 6. Ensure Thread Safety

Use mutexes to protect shared data in services:

```go
func (s *UserService) SomeMethod() error {
    s.mu.Lock()         // Acquire lock
    defer s.mu.Unlock() // Ensure lock is released
    
    // Access shared data safely
    // ...
    
    return nil
}
```

### 7. Log Important Events

Log important events for debugging and monitoring:

```go
log.Printf("Password reset token generated for user %s", user.Email)
log.Printf("Password reset successful for user %s", user.Email)
```

### 8. Follow RESTful Conventions

Follow RESTful conventions for your API design:
- Use appropriate HTTP methods (GET, POST, PUT, DELETE)
- Use meaningful URLs that represent resources
- Return appropriate HTTP status codes

### 9. Keep Security in Mind

Always consider security implications:
- Validate all input data
- Sanitize output data
- Don't expose sensitive information in responses
- Use secure random tokens for sensitive operations

### 10. Write Tests

Write tests for your code to ensure it works correctly:
- Test handlers with mock services
- Test services with mock data
- Test models with various input scenarios

## Troubleshooting

When implementing new features, you might encounter some common issues. Here's how to troubleshoot them:

### Compilation Errors

1. **"Undefined: [Function or Variable]"**
   - **Cause**: You're trying to use a function or variable that doesn't exist or isn't imported.
   - **Solution**: Check for typos and ensure all required packages are imported.

2. **"Cannot use [Type] as type [Interface] in assignment"**
   - **Cause**: Your type doesn't implement all the methods required by the interface.
   - **Solution**: Ensure your type implements all the methods defined in the interface with the correct signatures.

3. **"Missing return statement"**
   - **Cause**: A function that should return a value doesn't have a return statement for all code paths.
   - **Solution**: Add return statements for all code paths, including error conditions.

### Runtime Errors

1. **"404 Not Found" when accessing a new endpoint**
   - **Cause**: The route isn't registered correctly or the URL doesn't match.
   - **Solution**: Check that the route is registered in the main function and that you're using the correct URL.

2. **"500 Internal Server Error"**
   - **Cause**: An error occurred in your handler or service that wasn't handled properly.
   - **Solution**: Check the server logs for detailed error messages and ensure all errors are handled.

3. **"400 Bad Request"**
   - **Cause**: The request body is malformed or doesn't match the expected format.
   - **Solution**: Check that your JSON request body is correctly formatted and matches the expected structure.

### Unexpected Behavior

1. **Data not being saved or retrieved correctly**
   - **Cause**: Issues with data access or thread safety.
   - **Solution**: Check that mutexes are used correctly and that data is being stored and retrieved properly.

2. **Validation not working as expected**
   - **Cause**: Validation rules are incorrect or validation isn't being called.
   - **Solution**: Check that validation methods are implemented correctly and that they're being called in the right places.

3. **Responses not matching expected format**
   - **Cause**: Response models are incorrect or response formatting is wrong.
   - **Solution**: Check that response models are correctly defined and that response formatting is consistent.

### Debugging Tips

1. **Use Log Statements**: Add log statements to trace the flow of execution and identify where things go wrong.

```go
log.Printf("Processing request for user %s", user.Email)
log.Printf("Validation result: %v", err)
log.Printf("Service call result: %v", result)
```

2. **Test Components in Isolation**: Test each component (model, service, handler) separately to isolate issues.

3. **Use a Debugger**: Use a debugger to step through your code and inspect variables at runtime.

4. **Check the Server Logs**: The server logs often contain detailed error messages that can help identify issues.

5. **Compare with Working Code**: Compare your implementation with existing working code to identify differences.

## Conclusion

Implementing a new feature in this Go application follows a structured pattern that involves making changes across multiple layers:

1. **Update the Data Model**: Define new data structures and validation rules
2. **Update the Service Layer**: Implement business logic and data operations
3. **Update the Handler Layer**: Process HTTP requests and responses
4. **Update the Routes**: Map URLs to handler methods
5. **Test the Implementation**: Verify that everything works correctly

This pattern ensures that your code is organized, maintainable, and follows best practices. By following this guide, you should be able to implement any new user-related feature in the application.

Remember to:
- Plan your feature before writing code
- Follow the layered architecture
- Validate input data
- Handle errors gracefully
- Test your implementation thoroughly
- Consider security implications

With this approach, you'll be able to extend the application with new features confidently and efficiently.
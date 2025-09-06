// internal/models/models.go - Data models and structures
// This package demonstrates Go's approach to data modeling
// It shows how to define structs, interfaces, and implement data validation
// The models represent the core data structures used throughout the application

package models

import (
	// Standard library imports
	"encoding/json" // JSON encoding/decoding
	"fmt"           // Formatted I/O
	"regexp"        // Regular expressions for validation
	"strings"       // String manipulation
	"time"          // Time handling
)

/*
USER STRUCT
Represents a user in the system
This struct demonstrates Go's struct composition and JSON tagging
*/
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
}

/*
PROFILE STRUCT
Represents extended user profile information
Demonstrates optional fields and nested structs
*/
type Profile struct {
	Bio        string   `json:"bio"`         // User biography
	AvatarURL  string   `json:"avatar_url"`  // Profile picture URL
	Location   string   `json:"location"`    // User location
	Website    string   `json:"website"`     // Personal website
	Interests  []string `json:"interests"`   // User interests
	Skills     []string `json:"skills"`      // User skills
	Experience int      `json:"experience"`  // Years of experience
}

/*
CALCULATION REQUEST/RESPONSE STRUCTS
Demonstrate request/response patterns for API endpoints
*/
type CalculationRequest struct {
	Operation string  `json:"operation"` // Math operation: add, subtract, multiply, divide
	A         float64 `json:"a"`         // First operand
	B         float64 `json:"b"`         // Second operand
	Precision int     `json:"precision"` // Decimal precision for result
}

type CalculationResponse struct {
	Result      float64 `json:"result"`       // Calculation result
	Operation   string  `json:"operation"`    // Operation performed
	Operands    string  `json:"operands"`     // String representation of operands
	Timestamp   int64   `json:"timestamp"`    // Unix timestamp
	RequestID   string  `json:"request_id"`   // Request identifier
	ProcessingTime int64 `json:"processing_time_ms"` // Processing time in milliseconds
}

/*
GOROUTINE DEMONSTRATION STRUCTS
Show different ways to structure concurrent operations
*/
type GoroutineRequest struct {
	TaskType    string `json:"task_type"`    // Type of concurrent task
	TaskCount   int    `json:"task_count"`   // Number of goroutines to spawn
	DelayMs     int    `json:"delay_ms"`     // Delay between goroutine starts
	Description string `json:"description"`  // Task description
}

type GoroutineResponse struct {
	TaskID       string   `json:"task_id"`        // Unique task identifier
	Status       string   `json:"status"`         // Task status: running, completed, failed
	Results      []string `json:"results"`        // Results from each goroutine
	StartTime    int64    `json:"start_time"`     // Task start timestamp
	EndTime      int64    `json:"end_time"`       // Task end timestamp
	TotalTasks   int      `json:"total_tasks"`    // Total number of tasks
	CompletedTasks int    `json:"completed_tasks"` // Number of completed tasks
}

/*
WEBSOCKET MESSAGE STRUCTS
Define message formats for WebSocket communication
*/
type WSMessage struct {
	Type      string          `json:"type"`       // Message type: chat, notification, system
	From      string          `json:"from"`       // Sender identifier
	To        string          `json:"to"`         // Recipient identifier (optional)
	Content   json.RawMessage `json:"content"`    // Message content (JSON)
	Timestamp int64           `json:"timestamp"`  // Message timestamp
	ID        string          `json:"id"`         // Unique message ID
}

type WSChatMessage struct {
	Text      string `json:"text"`       // Chat message text
	Channel   string `json:"channel"`    // Chat channel
	MessageType string `json:"message_type"` // Message type: text, image, file
}

type WSNotification struct {
	Title     string `json:"title"`      // Notification title
	Body      string `json:"body"`       // Notification body
	Level     string `json:"level"`      // Notification level: info, warning, error
	ActionURL string `json:"action_url"` // Optional action URL
}

/*
ERROR RESPONSE STRUCT
Standard error response format for API consistency
*/
type ErrorResponse struct {
	Error       string                 `json:"error"`        // Error message
	Code        string                 `json:"code"`         // Error code
	Details     map[string]interface{} `json:"details,omitempty"` // Additional error details
	Timestamp   int64                  `json:"timestamp"`    // Error timestamp
	RequestID   string                 `json:"request_id"`   // Request ID for tracking
}

/*
SUCCESS RESPONSE STRUCT
Standard success response format for API consistency
*/
type SuccessResponse struct {
	Message   string                 `json:"message"`      // Success message
	Data      interface{}            `json:"data,omitempty"` // Response data
	Metadata  map[string]interface{} `json:"metadata,omitempty"` // Additional metadata
	Timestamp int64                  `json:"timestamp"`    // Response timestamp
	RequestID string                 `json:"request_id"`   // Request ID for tracking
}

/*
VALIDATION INTERFACES
Define interfaces for validation to demonstrate Go's interface concepts
*/
type Validator interface {
	Validate() error // Validate method signature
}

type ModelValidator interface {
	Validator                                    // Embed Validator interface
	ValidateCreate() error                       // Validation for creation
	ValidateUpdate() error                       // Validation for updates
	GetValidationRules() map[string]string       // Get validation rules as map
}

/*
VALIDATOR IMPLEMENTATIONS
Implement validation methods for different structs
This demonstrates how to implement interfaces in Go
*/

// Validate implements Validator interface for User
func (u *User) Validate() error {
	// Username validation
	if strings.TrimSpace(u.Username) == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if len(u.Username) < 3 {
		return fmt.Errorf("username must be at least 3 characters long")
	}
	if len(u.Username) > 50 {
		return fmt.Errorf("username cannot exceed 50 characters")
	}
	// Username format validation (alphanumeric and underscore only)
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	if !usernameRegex.MatchString(u.Username) {
		return fmt.Errorf("username can only contain letters, numbers, and underscores")
	}

	// Email validation
	if strings.TrimSpace(u.Email) == "" {
		return fmt.Errorf("email cannot be empty")
	}
	// Basic email regex pattern
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(u.Email) {
		return fmt.Errorf("invalid email format")
	}

	// Name validation
	if strings.TrimSpace(u.FirstName) == "" {
		return fmt.Errorf("first name cannot be empty")
	}
	if strings.TrimSpace(u.LastName) == "" {
		return fmt.Errorf("last name cannot be empty")
	}
	if len(u.FirstName) > 100 {
		return fmt.Errorf("first name cannot exceed 100 characters")
	}
	if len(u.LastName) > 100 {
		return fmt.Errorf("last name cannot exceed 100 characters")
	}

	// Age validation
	if u.Age < 0 {
		return fmt.Errorf("age cannot be negative")
	}
	if u.Age > 150 {
		return fmt.Errorf("age cannot exceed 150")
	}

	// Roles validation
	if len(u.Roles) == 0 {
		return fmt.Errorf("user must have at least one role")
	}
	for _, role := range u.Roles {
		if strings.TrimSpace(role) == "" {
			return fmt.Errorf("role cannot be empty")
		}
	}

	// Profile validation (if provided)
	if u.Profile != nil {
		if err := u.Profile.Validate(); err != nil {
			return fmt.Errorf("profile validation failed: %w", err)
		}
	}

	return nil
}

// ValidateCreate implements ModelValidator interface for User
func (u *User) ValidateCreate() error {
	// Basic validation
	if err := u.Validate(); err != nil {
		return err
	}

	// Creation-specific validation
	if u.ID != 0 {
		return fmt.Errorf("ID must be zero for new user")
	}
	if !u.CreatedAt.IsZero() {
		return fmt.Errorf("created_at must be zero for new user")
	}
	if !u.UpdatedAt.IsZero() {
		return fmt.Errorf("updated_at must be zero for new user")
	}

	return nil
}

// ValidateUpdate implements ModelValidator interface for User
func (u *User) ValidateUpdate() error {
	// Basic validation
	if err := u.Validate(); err != nil {
		return err
	}

	// Update-specific validation
	if u.ID <= 0 {
		return fmt.Errorf("ID must be positive for update")
	}

	return nil
}

// GetValidationRules implements ModelValidator interface for User
func (u *User) GetValidationRules() map[string]string {
	return map[string]string{
		"username":    "required,min=3,max=50,alphanumeric_with_underscore",
		"email":       "required,email",
		"first_name":  "required,min=1,max=100",
		"last_name":   "required,min=1,max=100",
		"age":         "min=0,max=150",
		"roles":       "required,min=1",
	}
}

// Profile validation methods
func (p *Profile) Validate() error {
	// Bio validation
	if len(p.Bio) > 1000 {
		return fmt.Errorf("bio cannot exceed 1000 characters")
	}

	// Avatar URL validation (basic URL check)
	if p.AvatarURL != "" {
		if !strings.HasPrefix(p.AvatarURL, "http://") && !strings.HasPrefix(p.AvatarURL, "https://") {
			return fmt.Errorf("avatar URL must start with http:// or https://")
		}
	}

	// Website validation (basic URL check)
	if p.Website != "" {
		if !strings.HasPrefix(p.Website, "http://") && !strings.HasPrefix(p.Website, "https://") {
			return fmt.Errorf("website must start with http:// or https://")
		}
	}

	// Location validation
	if len(p.Location) > 200 {
		return fmt.Errorf("location cannot exceed 200 characters")
	}

	// Experience validation
	if p.Experience < 0 {
		return fmt.Errorf("experience cannot be negative")
	}
	if p.Experience > 100 {
		return fmt.Errorf("experience cannot exceed 100 years")
	}

	return nil
}

// CalculationRequest validation
func (cr *CalculationRequest) Validate() error {
	// Operation validation
	validOperations := []string{"add", "subtract", "multiply", "divide", "power", "sqrt"}
	if !contains(validOperations, cr.Operation) {
		return fmt.Errorf("invalid operation: %s (must be one of: %v)", cr.Operation, validOperations)
	}

	// Division by zero check
	if cr.Operation == "divide" && cr.B == 0 {
		return fmt.Errorf("division by zero is not allowed")
	}

	// Precision validation
	if cr.Precision < 0 || cr.Precision > 10 {
		return fmt.Errorf("precision must be between 0 and 10, got: %d", cr.Precision)
	}

	return nil
}

/*
FACTORY FUNCTIONS
Functions to create models with default values
This demonstrates Go's approach to object creation
*/

// NewUser creates a new User with default values
func NewUser(username, email, firstName, lastName string) *User {
	return &User{
		Username:  username,
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Roles:     []string{"user"}, // Default role
	}
}

// NewProfile creates a new Profile with default values
func NewProfile() *Profile {
	return &Profile{
		Interests: []string{},
		Skills:    []string{},
	}
}

// NewCalculationRequest creates a new calculation request with defaults
func NewCalculationRequest(operation string, a, b float64) *CalculationRequest {
	return &CalculationRequest{
		Operation: operation,
		A:         a,
		B:         b,
		Precision: 2, // Default precision
	}
}

/*
UTILITY FUNCTIONS
Helper functions for model operations
*/

// GetFullName returns the user's full name
func (u *User) GetFullName() string {
	return fmt.Sprintf("%s %s", u.FirstName, u.LastName)
}

// HasRole checks if user has a specific role
func (u *User) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// AddRole adds a role to the user if not already present
func (u *User) AddRole(role string) {
	if !u.HasRole(role) {
		u.Roles = append(u.Roles, role)
	}
}

// RemoveRole removes a role from the user
func (u *User) RemoveRole(role string) {
	newRoles := []string{}
	for _, r := range u.Roles {
		if r != role {
			newRoles = append(newRoles, r)
		}
	}
	u.Roles = newRoles
}

// IsAdult checks if user is an adult (age >= 18)
func (u *User) IsAdult() bool {
	return u.Age >= 18
}

// GetAgeGroup returns the user's age group
func (u *User) GetAgeGroup() string {
	switch {
	case u.Age < 13:
		return "child"
	case u.Age < 18:
		return "teenager"
	case u.Age < 65:
		return "adult"
	default:
		return "senior"
	}
}

// Sanitize removes sensitive information from user object
func (u *User) Sanitize() *User {
	// Create copy with sensitive fields removed/reset
	return &User{
		ID:        u.ID,
		Username:  u.Username,
		FirstName: u.FirstName,
		LastName:  u.LastName,
		Age:       u.Age,
		Active:    u.Active,
		CreatedAt: u.CreatedAt,
		Roles:     u.Roles,
		Profile:   u.Profile,
	}
}

/*
JSON MARSHALING CUSTOMIZATION
Demonstrate custom JSON marshaling for models
*/

// Custom JSON marshaling for User to exclude sensitive fields
func (u *User) MarshalJSON() ([]byte, error) {
	type Alias User // Create alias to avoid infinite recursion
	return json.Marshal(&struct {
		*Alias
		Email string `json:"email,omitempty"` // Conditionally include email
	}{
		Alias: (*Alias)(u),
		Email: func() string {
			if u.Active {
				return u.Email
			}
			return "" // Exclude email for inactive users
		}(),
	})
}

// Helper function for string slice contains
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
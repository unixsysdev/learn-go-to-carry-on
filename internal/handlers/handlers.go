// internal/handlers/handlers.go - HTTP request handlers
// This package demonstrates Go's approach to HTTP request handling
// It shows how to structure handlers, parse requests, send responses,
// handle errors, and implement RESTful API patterns

package handlers

import (
	// Standard library imports
	"encoding/json"   // JSON encoding/decoding
	"fmt"             // Formatted I/O
	"io"              // I/O utilities
	"log"             // Logging
	"net/http"        // HTTP server and client
	"strconv"         // String conversion
	"strings"         // String manipulation
	"time"            // Time handling

	// Internal imports
	"scholastic-go-tutorial/internal/models"    // Data models
	"scholastic-go-tutorial/internal/services"  // Business services
)

/*
HANDLER STRUCTURES
Define handler structs that will contain service dependencies
This demonstrates dependency injection in HTTP handlers
*/

// APIHandler handles API-related HTTP requests
type APIHandler struct {
	userService UserServiceInterface
	mathService MathServiceInterface
}

// WebSocketHandler handles WebSocket connections
type WebSocketHandler struct {
	wsService WebSocketServiceInterface
}

// StaticHandler serves static files
type StaticHandler struct {
	rootPath string
}

/*
INTERFACE DEFINITIONS
Define interfaces for service dependencies to enable mocking and testing
*/

type UserServiceInterface interface {
	GetUserByID(id int) (*models.User, error)
	GetAllUsers() ([]*models.User, error)
	CreateUser(user *models.User) error
	UpdateUser(user *models.User) error
	DeleteUser(id int) error
	GetUserByUsername(username string) (*models.User, error)
	SearchUsers(query string) ([]*models.User, error)
}

type MathServiceInterface interface {
	Calculate(operation string, a, b float64) (float64, error)
	CalculateWithPrecision(operation string, a, b float64, precision int) (float64, error)
	GetCalculationHistory() []services.CalculationResult
	ClearHistory()
	PerformBulkCalculations(requests []models.CalculationRequest) []services.CalculationResult
}

type WebSocketServiceInterface interface {
	BroadcastMessage(message models.WSMessage) error
	SendMessage(userID string, message models.WSMessage) error
	GetConnectedUsers() []string
	RegisterUser(userID string) error
	UnregisterUser(userID string) error
}

/*
HANDLER CONSTRUCTOR FUNCTIONS
Create new handler instances with injected dependencies
*/

// NewAPIHandler creates a new APIHandler instance
func NewAPIHandler(userService UserServiceInterface, mathService MathServiceInterface) *APIHandler {
	return &APIHandler{
		userService: userService,
		mathService: mathService,
	}
}

// NewWebSocketHandler creates a new WebSocketHandler instance
func NewWebSocketHandler(wsService WebSocketServiceInterface) *WebSocketHandler {
	return &WebSocketHandler{
		wsService: wsService,
	}
}

// NewStaticHandler creates a new StaticHandler instance
func NewStaticHandler(rootPath string) *StaticHandler {
	return &StaticHandler{
		rootPath: rootPath,
	}
}

/*
HEALTH CHECK HANDLER
Simple endpoint to verify server is running
Demonstrates basic handler structure and response writing
*/

// HealthCheck handles health check requests
func (h *APIHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	// Create health check response
	response := models.SuccessResponse{
		Message:   "Server is healthy and running",
		Data: map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().Unix(),
			"service":   "Scholastic Go Tutorial API",
			"version":   "1.0.0",
		},
		Metadata: map[string]interface{}{
			"endpoint": "/health",
			"method":   r.Method,
		},
		Timestamp: time.Now().Unix(),
		RequestID: getRequestID(r),
	}
	
	// Send JSON response
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding health check response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

/*
USERS HANDLER
Handles CRUD operations for users
Demonstrates RESTful API patterns and request routing
*/

// UsersHandler handles requests for /api/users endpoint
func (h *APIHandler) UsersHandler(w http.ResponseWriter, r *http.Request) {
	// Route based on HTTP method
	switch r.Method {
	case http.MethodGet:
		h.getUsers(w, r)
	case http.MethodPost:
		h.createUser(w, r)
	default:
		// Method not allowed
		sendErrorResponse(w, "Method not allowed", "METHOD_NOT_ALLOWED", 
			http.StatusMethodNotAllowed, getRequestID(r))
	}
}

// getUsers handles GET /api/users - retrieve all users
func (h *APIHandler) getUsers(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	query := r.URL.Query().Get("search")
	
	var users []*models.User
	var err error
	
	// Get users based on search query
	if query != "" {
		users, err = h.userService.SearchUsers(query)
	} else {
		users, err = h.userService.GetAllUsers()
	}
	
	if err != nil {
		sendErrorResponse(w, "Failed to retrieve users", "USERS_RETRIEVAL_ERROR", 
			http.StatusInternalServerError, getRequestID(r))
		return
	}
	
	// Sanitize users before sending response
	sanitizedUsers := make([]*models.User, len(users))
	for i, user := range users {
		sanitizedUsers[i] = user.Sanitize()
	}
	
	// Send successful response
	response := models.SuccessResponse{
		Message: fmt.Sprintf("Successfully retrieved %d users", len(users)),
		Data:    sanitizedUsers,
		Metadata: map[string]interface{}{
			"count":     len(users),
			"search":    query,
			"timestamp": time.Now().Unix(),
		},
		Timestamp: time.Now().Unix(),
		RequestID: getRequestID(r),
	}
	
	sendJSONResponse(w, response, http.StatusOK)
}

// createUser handles POST /api/users - create new user
func (h *APIHandler) createUser(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var user models.User
	if err := parseJSONBody(r, &user); err != nil {
		sendErrorResponse(w, "Invalid request body", "INVALID_REQUEST_BODY", 
			http.StatusBadRequest, getRequestID(r))
		return
	}
	
	// Validate user data
	if err := user.ValidateCreate(); err != nil {
		sendErrorResponse(w, fmt.Sprintf("Validation failed: %v", err), "VALIDATION_ERROR", 
			http.StatusBadRequest, getRequestID(r))
		return
	}
	
	// Create user
	if err := h.userService.CreateUser(&user); err != nil {
		sendErrorResponse(w, fmt.Sprintf("Failed to create user: %v", err), "USER_CREATION_ERROR", 
			http.StatusConflict, getRequestID(r))
		return
	}
	
	// Send successful response with created user
	response := models.SuccessResponse{
		Message:   "User created successfully",
		Data:      user.Sanitize(),
		Metadata: map[string]interface{}{
			"user_id": user.ID,
		},
		Timestamp: time.Now().Unix(),
		RequestID: getRequestID(r),
	}
	
	sendJSONResponse(w, response, http.StatusCreated)
}

// UserHandler handles requests for /api/users/{id} endpoint
func (h *APIHandler) UserHandler(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from URL path
	idStr := strings.TrimPrefix(r.URL.Path, "/api/users/")
	if idStr == "" || idStr == r.URL.Path {
		sendErrorResponse(w, "User ID is required", "MISSING_USER_ID", 
			http.StatusBadRequest, getRequestID(r))
		return
	}
	
	// Convert ID to integer
	id, err := strconv.Atoi(idStr)
	if err != nil {
		sendErrorResponse(w, "Invalid user ID format", "INVALID_USER_ID", 
			http.StatusBadRequest, getRequestID(r))
		return
	}
	
	// Route based on HTTP method
	switch r.Method {
	case http.MethodGet:
		h.getUser(w, r, id)
	case http.MethodPut:
		h.updateUser(w, r, id)
	case http.MethodDelete:
		h.deleteUser(w, r, id)
	default:
		sendErrorResponse(w, "Method not allowed", "METHOD_NOT_ALLOWED", 
			http.StatusMethodNotAllowed, getRequestID(r))
	}
}

// getUser handles GET /api/users/{id} - retrieve specific user
func (h *APIHandler) getUser(w http.ResponseWriter, r *http.Request, id int) {
	user, err := h.userService.GetUserByID(id)
	if err != nil {
		sendErrorResponse(w, fmt.Sprintf("User not found: %v", err), "USER_NOT_FOUND", 
			http.StatusNotFound, getRequestID(r))
		return
	}
	
	response := models.SuccessResponse{
		Message:   "User retrieved successfully",
		Data:      user.Sanitize(),
		Timestamp: time.Now().Unix(),
		RequestID: getRequestID(r),
	}
	
	sendJSONResponse(w, response, http.StatusOK)
}

// updateUser handles PUT /api/users/{id} - update user
func (h *APIHandler) updateUser(w http.ResponseWriter, r *http.Request, id int) {
	// Parse request body
	var user models.User
	if err := parseJSONBody(r, &user); err != nil {
		sendErrorResponse(w, "Invalid request body", "INVALID_REQUEST_BODY", 
			http.StatusBadRequest, getRequestID(r))
		return
	}
	
	// Set user ID from URL
	user.ID = id
	
	// Validate user data
	if err := user.ValidateUpdate(); err != nil {
		sendErrorResponse(w, fmt.Sprintf("Validation failed: %v", err), "VALIDATION_ERROR", 
			http.StatusBadRequest, getRequestID(r))
		return
	}
	
	// Update user
	if err := h.userService.UpdateUser(&user); err != nil {
		sendErrorResponse(w, fmt.Sprintf("Failed to update user: %v", err), "USER_UPDATE_ERROR", 
			http.StatusInternalServerError, getRequestID(r))
		return
	}
	
	response := models.SuccessResponse{
		Message:   "User updated successfully",
		Data:      user.Sanitize(),
		Timestamp: time.Now().Unix(),
		RequestID: getRequestID(r),
	}
	
	sendJSONResponse(w, response, http.StatusOK)
}

// deleteUser handles DELETE /api/users/{id} - delete user
func (h *APIHandler) deleteUser(w http.ResponseWriter, r *http.Request, id int) {
	if err := h.userService.DeleteUser(id); err != nil {
		sendErrorResponse(w, fmt.Sprintf("Failed to delete user: %v", err), "USER_DELETE_ERROR", 
			http.StatusNotFound, getRequestID(r))
		return
	}
	
	response := models.SuccessResponse{
		Message:   "User deleted successfully",
		Timestamp: time.Now().Unix(),
		RequestID: getRequestID(r),
	}
	
	sendJSONResponse(w, response, http.StatusOK)
}

/*
CALCULATION HANDLER
Demonstrates mathematical operations and bulk calculations
*/

// CalculateHandler handles POST /api/calculate - perform calculations
func (h *APIHandler) CalculateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendErrorResponse(w, "Method not allowed", "METHOD_NOT_ALLOWED", 
			http.StatusMethodNotAllowed, getRequestID(r))
		return
	}
	
	// Parse request body
	var request models.CalculationRequest
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
	
	// Perform calculation
	result, err := h.mathService.CalculateWithPrecision(
		request.Operation,
		request.A,
		request.B,
		request.Precision,
	)
	
	if err != nil {
		sendErrorResponse(w, fmt.Sprintf("Calculation failed: %v", err), "CALCULATION_ERROR", 
			http.StatusBadRequest, getRequestID(r))
		return
	}
	
	// Create response
	calcResponse := models.CalculationResponse{
		Result:    result,
		Operation: request.Operation,
		Operands:  fmt.Sprintf("%.2f, %.2f", request.A, request.B),
		Timestamp: time.Now().Unix(),
		RequestID: getRequestID(r),
	}
	
	response := models.SuccessResponse{
		Message:   "Calculation completed successfully",
		Data:      calcResponse,
		Timestamp: time.Now().Unix(),
		RequestID: getRequestID(r),
	}
	
	sendJSONResponse(w, response, http.StatusOK)
}

/*
GOROUTINE DEMONSTRATION HANDLER
Shows various goroutine patterns and concurrency concepts
*/

// GoroutineHandler handles POST /api/goroutines - demonstrate goroutines
func (h *APIHandler) GoroutineHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendErrorResponse(w, "Method not allowed", "METHOD_NOT_ALLOWED", 
			http.StatusMethodNotAllowed, getRequestID(r))
		return
	}
	
	// Parse request body for different goroutine patterns
	var request models.GoroutineRequest
	if err := parseJSONBody(r, &request); err != nil {
		sendErrorResponse(w, "Invalid request body", "INVALID_REQUEST_BODY", 
			http.StatusBadRequest, getRequestID(r))
		return
	}
	
	// Validate request
	if request.TaskCount <= 0 {
		sendErrorResponse(w, "Task count must be positive", "VALIDATION_ERROR", 
			http.StatusBadRequest, getRequestID(r))
		return
	}
	
	// Create goroutine service for demonstration
	goroutineService := services.NewGoroutineService()
	
	var results []string
	var err error
	
	// Execute different goroutine patterns based on task type
	switch request.TaskType {
	case "basic":
		results, err = goroutineService.RunConcurrentTask("basic_concurrent", request.TaskCount)
	case "pipeline":
		// Run pipeline with multiple stages
		inputs := make([]int, request.TaskCount)
		for i := 0; i < request.TaskCount; i++ {
			inputs[i] = i + 1
		}
		
		// Define pipeline stages
		stages := []func(int) int{
			func(x int) int { return x * 2 },      // Stage 1: multiply by 2
			func(x int) int { return x + 10 },     // Stage 2: add 10
			func(x int) int { return x / 2 },      // Stage 3: divide by 2
		}
		
		pipelineResults, pipelineErr := goroutineService.RunPipeline(inputs, stages...)
		if pipelineErr != nil {
			err = pipelineErr
		} else {
			// Convert results to strings for response
			results = make([]string, len(pipelineResults))
			for i, result := range pipelineResults {
				results[i] = fmt.Sprintf("Pipeline result %d: %d", i+1, result)
			}
		}
	case "worker_pool":
		// Create jobs for worker pool
		jobs := make([]string, request.TaskCount)
		for i := 0; i < request.TaskCount; i++ {
			jobs[i] = fmt.Sprintf("job_%d", i+1)
		}
		
		results, err = goroutineService.RunWorkerPool(jobs, 3) // 3 workers
		
	case "fan_out_fan_in":
		// Create inputs for fan-out/fan-in
		inputs := make([]int, request.TaskCount)
		for i := 0; i < request.TaskCount; i++ {
			inputs[i] = i + 1
		}
		
		fofiResults, fofiErr := goroutineService.RunFanOutFanIn(inputs, 4) // 4 workers
		if fofiErr != nil {
			err = fofiErr
		} else {
			// Convert results to strings for response
			results = make([]string, len(fofiResults))
			for i, result := range fofiResults {
				results[i] = fmt.Sprintf("Fan-out/fan-in result %d: %d", i+1, result)
			}
		}
	default:
		sendErrorResponse(w, fmt.Sprintf("Unknown task type: %s", request.TaskType), 
			"INVALID_TASK_TYPE", http.StatusBadRequest, getRequestID(r))
		return
	}
	
	if err != nil {
		sendErrorResponse(w, fmt.Sprintf("Goroutine task failed: %v", err), 
			"GOROUTINE_ERROR", http.StatusInternalServerError, getRequestID(r))
		return
	}
	
	// Create response
	goroutineResponse := models.GoroutineResponse{
		TaskID:         fmt.Sprintf("goroutine_task_%d", time.Now().UnixNano()),
		Status:         "completed",
		Results:        results,
		StartTime:      time.Now().Unix(),
		EndTime:        time.Now().Unix(),
		TotalTasks:     request.TaskCount,
		CompletedTasks: len(results),
	}
	
	response := models.SuccessResponse{
		Message:   "Goroutine demonstration completed successfully",
		Data:      goroutineResponse,
		Metadata: map[string]interface{}{
			"task_type":   request.TaskType,
			"task_count":  request.TaskCount,
			"description": request.Description,
		},
		Timestamp: time.Now().Unix(),
		RequestID: getRequestID(r),
	}
	
	sendJSONResponse(w, response, http.StatusOK)
}

/*
WEBSOCKET HANDLER
Handles WebSocket connections and message exchange
*/

// HandleWebSocket handles WebSocket upgrade and message exchange
func (h *WebSocketHandler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	// For demonstration, we'll simulate WebSocket behavior with HTTP
	// In a real implementation, you would use gorilla/websocket or similar library
	
	switch r.Method {
	case http.MethodGet:
		h.getConnectedUsers(w, r)
	case http.MethodPost:
		h.handleWebSocketMessage(w, r)
	default:
		sendErrorResponse(w, "Method not allowed", "METHOD_NOT_ALLOWED", 
			http.StatusMethodNotAllowed, getRequestID(r))
	}
}

// getConnectedUsers handles GET /ws - get connected users
func (h *WebSocketHandler) getConnectedUsers(w http.ResponseWriter, r *http.Request) {
	users := h.wsService.GetConnectedUsers()
	
	response := models.SuccessResponse{
		Message:   "Connected users retrieved successfully",
		Data:      users,
		Metadata: map[string]interface{}{
			"count": len(users),
		},
		Timestamp: time.Now().Unix(),
		RequestID: getRequestID(r),
	}
	
	sendJSONResponse(w, response, http.StatusOK)
}

// handleWebSocketMessage handles POST /ws - send WebSocket message
func (h *WebSocketHandler) handleWebSocketMessage(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var message models.WSMessage
	if err := parseJSONBody(r, &message); err != nil {
		sendErrorResponse(w, "Invalid request body", "INVALID_REQUEST_BODY", 
			http.StatusBadRequest, getRequestID(r))
		return
	}
	
	// Validate message
	if message.Type == "" {
		sendErrorResponse(w, "Message type is required", "VALIDATION_ERROR", 
			http.StatusBadRequest, getRequestID(r))
		return
	}
	
	// Set timestamp and ID if not provided
	if message.Timestamp == 0 {
		message.Timestamp = time.Now().Unix()
	}
	if message.ID == "" {
		message.ID = fmt.Sprintf("msg_%d", time.Now().UnixNano())
	}
	
	// Handle different message types
	switch message.Type {
	case "broadcast":
		if err := h.wsService.BroadcastMessage(message); err != nil {
			sendErrorResponse(w, fmt.Sprintf("Broadcast failed: %v", err), 
				"BROADCAST_ERROR", http.StatusInternalServerError, getRequestID(r))
			return
		}
		
	case "direct":
		if message.To == "" {
			sendErrorResponse(w, "Recipient is required for direct messages", 
				"MISSING_RECIPIENT", http.StatusBadRequest, getRequestID(r))
			return
		}
		
		if err := h.wsService.SendMessage(message.To, message); err != nil {
			sendErrorResponse(w, fmt.Sprintf("Message delivery failed: %v", err), 
				"DELIVERY_ERROR", http.StatusInternalServerError, getRequestID(r))
			return
		}
		
	default:
		sendErrorResponse(w, fmt.Sprintf("Unsupported message type: %s", message.Type), 
			"UNSUPPORTED_MESSAGE_TYPE", http.StatusBadRequest, getRequestID(r))
		return
	}
	
	response := models.SuccessResponse{
		Message:   "Message sent successfully",
		Data:      message,
		Timestamp: time.Now().Unix(),
		RequestID: getRequestID(r),
	}
	
	sendJSONResponse(w, response, http.StatusOK)
}

/*
STATIC FILE HANDLER
Serves static files (HTML, CSS, JavaScript, images)
*/

// ServeHTTP implements http.Handler interface for StaticHandler
func (h *StaticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Add security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	
	// Create file server
	fileServer := http.FileServer(http.Dir(h.rootPath))
	
	// Serve files
	fileServer.ServeHTTP(w, r)
}

/*
UTILITY FUNCTIONS
Helper functions used across handlers
*/

// parseJSONBody parses JSON request body into the provided struct
func parseJSONBody(r *http.Request, v interface{}) error {
	// Set maximum request body size (1MB)
	r.Body = http.MaxBytesReader(nil, r.Body, 1024*1024)
	
	// Create JSON decoder
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // Reject unknown fields
	
	// Decode JSON
	if err := decoder.Decode(v); err != nil {
		return fmt.Errorf("JSON decode error: %w", err)
	}
	
	// Verify there's no extra data
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("request body must contain only one JSON object")
	}
	
	return nil
}

// sendJSONResponse sends a JSON response with the specified status code
func sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// sendErrorResponse sends a standardized error response
func sendErrorResponse(w http.ResponseWriter, message, code string, statusCode int, requestID string) {
	errorResponse := models.ErrorResponse{
		Error:     message,
		Code:      code,
		Timestamp: time.Now().Unix(),
		RequestID: requestID,
	}
	
	sendJSONResponse(w, errorResponse, statusCode)
}

// getRequestID extracts request ID from request context
func getRequestID(r *http.Request) string {
	// In a real implementation, this would get the request ID from context
	// For now, we'll generate a simple ID
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}
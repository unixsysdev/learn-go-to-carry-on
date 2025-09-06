// internal/services/services.go - Business logic services
// This package demonstrates Go's approach to service-oriented architecture
// It shows how to structure business logic, use interfaces, implement goroutines,
// channels, and various Go concurrency patterns

package services

import (
	// Standard library imports
	"fmt"             // Formatted I/O
	"log"             // Logging
	"math"            // Mathematical functions
	"math/rand"       // Random number generation
	"runtime"         // Runtime information
	"strings"         // String manipulation
	"sync"            // Synchronization primitives
	"time"            // Time handling

	// Internal imports
	"scholastic-go-tutorial/internal/models" // Data models
)

/*
SERVICE INTERFACES
Define interfaces for different services to demonstrate dependency injection
and interface segregation principles
*/

// UserServiceInterface defines the contract for user-related operations
type UserServiceInterface interface {
	GetUserByID(id int) (*models.User, error)
	GetAllUsers() ([]*models.User, error)
	CreateUser(user *models.User) error
	UpdateUser(user *models.User) error
	DeleteUser(id int) error
	GetUserByUsername(username string) (*models.User, error)
	SearchUsers(query string) ([]*models.User, error)
}

// MathServiceInterface defines the contract for mathematical operations
type MathServiceInterface interface {
	Calculate(operation string, a, b float64) (float64, error)
	CalculateWithPrecision(operation string, a, b float64, precision int) (float64, error)
	GetCalculationHistory() []CalculationResult
	ClearHistory()
	PerformBulkCalculations(requests []models.CalculationRequest) []CalculationResult
}

// WebSocketServiceInterface defines the contract for WebSocket operations
type WebSocketServiceInterface interface {
	BroadcastMessage(message models.WSMessage) error
	SendMessage(userID string, message models.WSMessage) error
	GetConnectedUsers() []string
	RegisterUser(userID string) error
	UnregisterUser(userID string) error
}

// GoroutineServiceInterface defines the contract for goroutine demonstrations
type GoroutineServiceInterface interface {
	RunConcurrentTask(taskType string, count int) ([]string, error)
	RunPipeline(input []int, stages ...func(int) int) ([]int, error)
	RunWorkerPool(jobs []string, workers int) ([]string, error)
	RunFanOutFanIn(inputs []int, workers int) ([]int, error)
}

/*
USER SERVICE IMPLEMENTATION
Implements user-related business logic
*/
type UserService struct {
	users  map[int]*models.User   // In-memory user storage (for demonstration)
	mu     sync.RWMutex           // Read-write mutex for concurrent access
	nextID int                    // Next available user ID
}

// NewUserService creates a new UserService instance
func NewUserService(cfg interface{}) *UserService {
	service := &UserService{
		users:  make(map[int]*models.User),
		nextID: 1,
	}
	
	// Initialize with some sample users for demonstration
	service.initializeSampleUsers()
	
	return service
}

// initializeSampleUsers creates sample users for demonstration
func (s *UserService) initializeSampleUsers() {
	sampleUsers := []*models.User{
		models.NewUser("alice_dev", "alice@example.com", "Alice", "Johnson"),
		models.NewUser("bob_coder", "bob@example.com", "Bob", "Smith"),
		models.NewUser("charlie_go", "charlie@example.com", "Charlie", "Brown"),
		models.NewUser("diana_admin", "diana@example.com", "Diana", "Wilson"),
		models.NewUser("eve_tester", "eve@example.com", "Eve", "Davis"),
	}

	// Set additional properties for sample users
	for i, user := range sampleUsers {
		user.ID = s.nextID
		user.Age = 25 + i*5
		user.Roles = []string{"user"}
		
		// Add different roles to demonstrate role-based access
		switch user.Username {
		case "alice_dev":
			user.AddRole("developer")
			user.Profile = &models.Profile{
				Bio:       "Senior Go developer with 5+ years experience",
				Location:  "San Francisco, CA",
				Skills:    []string{"Go", "Docker", "Kubernetes", "PostgreSQL"},
				Experience: 5,
			}
		case "bob_coder":
			user.AddRole("developer")
			user.Profile = &models.Profile{
				Bio:       "Full-stack developer passionate about clean code",
				Location:  "Austin, TX",
				Skills:    []string{"JavaScript", "React", "Node.js", "MongoDB"},
				Experience: 3,
			}
		case "charlie_go":
			user.AddRole("developer")
			user.Roles = append(user.Roles, "mentor")
			user.Profile = &models.Profile{
				Bio:       "Go enthusiast and open source contributor",
				Location:  "Seattle, WA",
				Skills:    []string{"Go", "Python", "AWS", "Microservices"},
				Experience: 7,
			}
		case "diana_admin":
			user.AddRole("admin")
			user.Profile = &models.Profile{
				Bio:       "System administrator and DevOps engineer",
				Location:  "New York, NY",
				Skills:    []string{"Linux", "AWS", "Docker", "CI/CD"},
				Experience: 6,
			}
		case "eve_tester":
			user.AddRole("tester")
			user.Profile = &models.Profile{
				Bio:       "QA engineer focused on automation testing",
				Location:  "Chicago, IL",
				Skills:    []string{"Selenium", "Python", "Jest", "Cypress"},
				Experience: 4,
			}
		}

		s.users[user.ID] = user
		s.nextID++
	}
}

// GetUserByID retrieves a user by ID with thread-safe access
func (s *UserService) GetUserByID(id int) (*models.User, error) {
	s.mu.RLock()         // Acquire read lock
	defer s.mu.RUnlock() // Ensure lock is released
	
	user, exists := s.users[id]
	if !exists {
		return nil, fmt.Errorf("user with ID %d not found", id)
	}
	
	// Return a copy to prevent external modification
	userCopy := *user
	return &userCopy, nil
}

// GetAllUsers retrieves all users with thread-safe access
func (s *UserService) GetAllUsers() ([]*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	users := make([]*models.User, 0, len(s.users))
	for _, user := range s.users {
		userCopy := *user
		users = append(users, &userCopy)
	}
	
	return users, nil
}

// CreateUser creates a new user with validation
func (s *UserService) CreateUser(user *models.User) error {
	// Validate user data
	if err := user.ValidateCreate(); err != nil {
		return fmt.Errorf("user validation failed: %w", err)
	}
	
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Check if username already exists
	for _, existingUser := range s.users {
		if existingUser.Username == user.Username {
			return fmt.Errorf("username '%s' already exists", user.Username)
		}
		if existingUser.Email == user.Email {
			return fmt.Errorf("email '%s' already exists", user.Email)
		}
	}
	
	// Assign ID and timestamps
	user.ID = s.nextID
	s.nextID++
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	
	// Store user
	s.users[user.ID] = user
	
	return nil
}

// UpdateUser updates an existing user
func (s *UserService) UpdateUser(user *models.User) error {
	if err := user.ValidateUpdate(); err != nil {
		return fmt.Errorf("user validation failed: %w", err)
	}
	
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Check if user exists
	if _, exists := s.users[user.ID]; !exists {
		return fmt.Errorf("user with ID %d not found", user.ID)
	}
	
	// Update timestamp
	user.UpdatedAt = time.Now()
	
	// Update user
	s.users[user.ID] = user
	
	return nil
}

// DeleteUser deletes a user by ID
func (s *UserService) DeleteUser(id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if _, exists := s.users[id]; !exists {
		return fmt.Errorf("user with ID %d not found", id)
	}
	
	delete(s.users, id)
	return nil
}

// GetUserByUsername retrieves a user by username
func (s *UserService) GetUserByUsername(username string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	for _, user := range s.users {
		if user.Username == username {
			userCopy := *user
			return &userCopy, nil
		}
	}
	
	return nil, fmt.Errorf("user with username '%s' not found", username)
}

// SearchUsers searches users by query string
func (s *UserService) SearchUsers(query string) ([]*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return s.GetAllUsers()
	}
	
	var results []*models.User
	for _, user := range s.users {
		// Search in username, first name, last name, and email
		if strings.Contains(strings.ToLower(user.Username), query) ||
			strings.Contains(strings.ToLower(user.FirstName), query) ||
			strings.Contains(strings.ToLower(user.LastName), query) ||
			strings.Contains(strings.ToLower(user.Email), query) {
			
			userCopy := *user
			results = append(results, &userCopy)
		}
	}
	
	return results, nil
}

/*
MATH SERVICE IMPLEMENTATION
Demonstrates mathematical operations and calculation history
*/
type MathService struct {
	history []CalculationResult // Calculation history
	mu      sync.RWMutex        // Mutex for history access
}

// CalculationResult represents a single calculation result
type CalculationResult struct {
	Operation      string    `json:"operation"`
	Operands       string    `json:"operands"`
	Result         float64   `json:"result"`
	Timestamp      int64     `json:"timestamp"`
	RequestID      string    `json:"request_id"`
	ProcessingTime int64     `json:"processing_time_ms"`
	Error          string    `json:"error,omitempty"`
}

// NewMathService creates a new MathService instance
func NewMathService() *MathService {
	return &MathService{
		history: make([]CalculationResult, 0),
	}
}

// Calculate performs a mathematical calculation
func (s *MathService) Calculate(operation string, a, b float64) (float64, error) {
	return s.CalculateWithPrecision(operation, a, b, 2)
}

// CalculateWithPrecision performs calculation with specified precision
func (s *MathService) CalculateWithPrecision(operation string, a, b float64, precision int) (float64, error) {
	startTime := time.Now()
	requestID := fmt.Sprintf("calc_%d", time.Now().UnixNano())
	
	var result float64
	var err error
	
	// Perform calculation based on operation
	switch operation {
	case "add":
		result = a + b
	case "subtract":
		result = a - b
	case "multiply":
		result = a * b
	case "divide":
		if b == 0 {
			err = fmt.Errorf("division by zero")
		} else {
			result = a / b
		}
	case "power":
		result = math.Pow(a, b)
	case "sqrt":
		if a < 0 {
			err = fmt.Errorf("cannot calculate square root of negative number")
		} else {
			result = math.Sqrt(a)
		}
	case "sin":
		result = math.Sin(a)
	case "cos":
		result = math.Cos(a)
	case "tan":
		result = math.Tan(a)
	case "log":
		if a <= 0 {
			err = fmt.Errorf("cannot calculate logarithm of non-positive number")
		} else {
			result = math.Log(a)
		}
	default:
		err = fmt.Errorf("unsupported operation: %s", operation)
	}
	
	processingTime := time.Since(startTime).Milliseconds()
	
	// Round result to specified precision
	if err == nil {
		multiplier := math.Pow(10, float64(precision))
		result = math.Round(result*multiplier) / multiplier
	}
	
	// Record calculation in history
	calcResult := CalculationResult{
		Operation:      operation,
		Operands:       fmt.Sprintf("%.2f, %.2f", a, b),
		Result:         result,
		Timestamp:      time.Now().Unix(),
		RequestID:      requestID,
		ProcessingTime: processingTime,
	}
	if err != nil {
		calcResult.Error = err.Error()
	}
	
	s.recordCalculation(calcResult)
	
	return result, err
}

// recordCalculation adds a calculation result to history
func (s *MathService) recordCalculation(result CalculationResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Add to history
	s.history = append(s.history, result)
	
	// Keep only last 100 calculations to prevent memory growth
	if len(s.history) > 100 {
		s.history = s.history[len(s.history)-100:]
	}
}

// GetCalculationHistory returns the calculation history
func (s *MathService) GetCalculationHistory() []CalculationResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	// Return a copy of the history
	historyCopy := make([]CalculationResult, len(s.history))
	copy(historyCopy, s.history)
	return historyCopy
}

// ClearHistory clears the calculation history
func (s *MathService) ClearHistory() {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.history = make([]CalculationResult, 0)
}

// PerformBulkCalculations performs multiple calculations concurrently
func (s *MathService) PerformBulkCalculations(requests []models.CalculationRequest) []CalculationResult {
	if len(requests) == 0 {
		return []CalculationResult{}
	}
	
	// Create channels for results
	results := make([]CalculationResult, len(requests))
	resultChan := make(chan struct {
		index int
		result CalculationResult
	}, len(requests))
	
	// Create worker goroutines
	var wg sync.WaitGroup
	maxWorkers := runtime.NumCPU() // Use number of CPU cores
	
	// Create job channel
	jobs := make(chan struct {
		index int
		request models.CalculationRequest
	}, len(requests))
	
	// Start worker goroutines
	for w := 0; w < maxWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			for job := range jobs {
				startTime := time.Now()
				
				// Perform calculation
				result, err := s.CalculateWithPrecision(
					job.request.Operation,
					job.request.A,
					job.request.B,
					job.request.Precision,
				)
				
				calcResult := CalculationResult{
					Operation:      job.request.Operation,
					Operands:       fmt.Sprintf("%.2f, %.2f", job.request.A, job.request.B),
					Result:         result,
					Timestamp:      time.Now().Unix(),
					RequestID:      fmt.Sprintf("bulk_%d_%d", workerID, time.Now().UnixNano()),
					ProcessingTime: time.Since(startTime).Milliseconds(),
				}
				if err != nil {
					calcResult.Error = err.Error()
				}
				
				resultChan <- struct {
					index int
					result CalculationResult
				}{job.index, calcResult}
			}
		}(w)
	}
	
	// Send jobs to workers
	for i, request := range requests {
		jobs <- struct {
			index int
			request models.CalculationRequest
		}{i, request}
	}
	close(jobs)
	
	// Wait for all workers to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	// Collect results
	for result := range resultChan {
		results[result.index] = result.result
	}
	
	return results
}

/*
WEBSOCKET SERVICE IMPLEMENTATION
Demonstrates WebSocket-like functionality and message broadcasting
*/
type WebSocketService struct {
	connections map[string]chan models.WSMessage // User ID to message channel mapping
	mu          sync.RWMutex                     // Mutex for connection access
}

// NewWebSocketService creates a new WebSocketService instance
func NewWebSocketService() *WebSocketService {
	return &WebSocketService{
		connections: make(map[string]chan models.WSMessage),
	}
}

// RegisterUser registers a user for WebSocket communication
func (s *WebSocketService) RegisterUser(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if _, exists := s.connections[userID]; exists {
		return fmt.Errorf("user %s is already registered", userID)
	}
	
	// Create message channel with buffer
	s.connections[userID] = make(chan models.WSMessage, 100)
	
	return nil
}

// UnregisterUser removes a user from WebSocket communication
func (s *WebSocketService) UnregisterUser(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	channel, exists := s.connections[userID]
	if !exists {
		return fmt.Errorf("user %s is not registered", userID)
	}
	
	// Close the channel and remove the connection
	close(channel)
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
	
	// Send message to all users concurrently
	var wg sync.WaitGroup
	errors := make(chan error, len(s.connections))
	
	for userID, channel := range s.connections {
		wg.Add(1)
		go func(id string, ch chan models.WSMessage) {
			defer wg.Done()
			
			select {
			case ch <- message:
				// Message sent successfully
			case <-time.After(5 * time.Second):
				errors <- fmt.Errorf("timeout sending message to user %s", id)
			}
		}(userID, channel)
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
	channel, exists := s.connections[userID]
	s.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("user %s is not connected", userID)
	}
	
	select {
	case channel <- message:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout sending message to user %s", userID)
	}
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

/*
GOROUTINE SERVICE IMPLEMENTATION
Demonstrates various goroutine patterns and concurrency concepts
*/
type GoroutineService struct{}

// NewGoroutineService creates a new GoroutineService instance
func NewGoroutineService() *GoroutineService {
	return &GoroutineService{}
}

// RunConcurrentTask demonstrates basic goroutine usage
func (s *GoroutineService) RunConcurrentTask(taskType string, count int) ([]string, error) {
	if count <= 0 {
		return nil, fmt.Errorf("task count must be positive")
	}
	
	results := make([]string, count)
	resultChan := make(chan struct {
		index int
		result string
	}, count)
	
	// Launch goroutines
	for i := 0; i < count; i++ {
		go func(index int) {
			// Simulate work with random delay
			delay := time.Duration(rand.Intn(100)) * time.Millisecond
			time.Sleep(delay)
			
			result := fmt.Sprintf("Task %d of type '%s' completed on goroutine %d (delay: %v)",
				index+1, taskType, index, delay)
			
			resultChan <- struct {
				index int
				result string
			}{index, result}
			
			// Log goroutine completion
			log.Printf("Goroutine %d completed task %d", index, index+1)
		}(i)
	}
	
	// Collect results
	for i := 0; i < count; i++ {
		result := <-resultChan
		results[result.index] = result.result
	}
	
	close(resultChan)
	return results, nil
}

// RunPipeline demonstrates pipeline pattern with goroutines
func (s *GoroutineService) RunPipeline(input []int, stages ...func(int) int) ([]int, error) {
	if len(input) == 0 {
		return []int{}, nil
	}
	
	if len(stages) == 0 {
		return input, nil // No stages, return input as-is
	}
	
	// Create channels for pipeline stages
	channels := make([]chan int, len(stages)+1)
	for i := range channels {
		channels[i] = make(chan int, len(input))
	}
	
	// Start pipeline stages
	var wg sync.WaitGroup
	
	// Input stage
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(channels[0])
		for _, value := range input {
			channels[0] <- value
		}
	}()
	
	// Processing stages
	for i, stage := range stages {
		wg.Add(1)
		go func(stageIndex int, stageFunc func(int) int) {
			defer wg.Done()
			defer close(channels[stageIndex+1])
			
			for value := range channels[stageIndex] {
				processed := stageFunc(value)
				channels[stageIndex+1] <- processed
			}
		}(i, stage)
	}
	
	// Output collection
	wg.Add(1)
	results := make([]int, 0, len(input))
	go func() {
		defer wg.Done()
		for value := range channels[len(stages)] {
			results = append(results, value)
		}
	}()
	
	wg.Wait()
	return results, nil
}

// RunWorkerPool demonstrates worker pool pattern
func (s *GoroutineService) RunWorkerPool(jobs []string, workers int) ([]string, error) {
	if len(jobs) == 0 {
		return []string{}, nil
	}
	
	if workers <= 0 {
		workers = runtime.NumCPU() // Default to number of CPU cores
	}
	
	// Create job and result channels
	jobsChan := make(chan string, len(jobs))
	resultsChan := make(chan string, len(jobs))
	
	// Start worker goroutines
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			for job := range jobsChan {
				// Process job
				result := fmt.Sprintf("Worker %d processed job: %s", workerID, job)
				
				// Simulate work
				time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
				
				resultsChan <- result
				log.Printf("Worker %d completed job: %s", workerID, job)
			}
		}(w)
	}
	
	// Send jobs to workers
	go func() {
		for _, job := range jobs {
			jobsChan <- job
		}
		close(jobsChan)
	}()
	
	// Wait for all workers to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()
	
	// Collect results
	results := make([]string, 0, len(jobs))
	for result := range resultsChan {
		results = append(results, result)
	}
	
	return results, nil
}

// RunFanOutFanIn demonstrates fan-out/fan-in pattern
func (s *GoroutineService) RunFanOutFanIn(inputs []int, workers int) ([]int, error) {
	if len(inputs) == 0 {
		return []int{}, nil
	}
	
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	
	// Fan out: distribute work among workers
	inputChan := make(chan int, len(inputs))
	resultChan := make(chan int, len(inputs))
	
	// Start worker goroutines
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			for input := range inputChan {
				// Process input (square it as example)
				result := input * input
				
				// Simulate work
				time.Sleep(time.Duration(rand.Intn(50)) * time.Millisecond)
				
				resultChan <- result
				log.Printf("Worker %d processed input %d -> result %d", workerID, input, result)
			}
		}(w)
	}
	
	// Send inputs to workers
	go func() {
		for _, input := range inputs {
			inputChan <- input
		}
		close(inputChan)
	}()
	
	// Wait for all workers to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	// Fan in: collect results from all workers
	results := make([]int, 0, len(inputs))
	for result := range resultChan {
		results = append(results, result)
	}
	
	return results, nil
}
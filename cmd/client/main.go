// cmd/client/main.go - HTTP client demonstrating Go concepts
// This client demonstrates various Go features including HTTP communication,
// goroutines, channels, error handling, and concurrent programming
// It serves as a comprehensive example of building HTTP clients in Go

package main

import (
	// Standard library imports
	"bytes"           // Buffer operations for request bodies
	"context"         // Context for request lifecycle management
	"encoding/json"   // JSON encoding/decoding
	"fmt"             // Formatted I/O
	"log"             // Logging
	"net/http"        // HTTP client implementation
	"os"              // Operating system interface
	"os/signal"       // Signal handling for graceful shutdown
	"strings"         // String manipulation
	"sync"            // Synchronization primitives
	"syscall"         // System calls
	"time"            // Time handling

	// Internal imports
	"scholastic-go-tutorial/internal/models" // Data models
)

/*
CLIENT CONFIGURATION
Structure to hold client configuration and settings
*/
type ClientConfig struct {
	BaseURL     string        // Base URL for API requests
	Timeout     time.Duration // Request timeout
	MaxRetries  int           // Maximum number of retries
	RetryDelay  time.Duration // Delay between retries
	UserAgent   string        // User-Agent header value
	AuthToken   string        // Authentication token
	Debug       bool          // Enable debug logging
	MaxWorkers  int           // Maximum concurrent workers
	BufferSize  int           // Channel buffer size
}

/*
HTTP CLIENT STRUCT
Custom HTTP client with additional functionality
*/
type HTTPClient struct {
	client      *http.Client  // Underlying HTTP client
	config      *ClientConfig // Client configuration
	baseURL     string        // Base URL for requests
	authToken   string        // Authentication token
	debug       bool          // Debug mode flag
	userAgent   string        // User-Agent header
}

/*
REQUEST/RESPONSE STRUCTS
Structures for organizing request and response data
*/

// APIRequest represents a generic API request
type APIRequest struct {
	Method      string                 `json:"method"`
	Endpoint    string                 `json:"endpoint"`
	Headers     map[string]string      `json:"headers"`
	Body        interface{}            `json:"body"`
	Timeout     time.Duration          `json:"timeout"`
	RetryCount  int                    `json:"retry_count"`
	RequestID   string                 `json:"request_id"`
}

// APIResponse represents a generic API response
type APIResponse struct {
	StatusCode  int                    `json:"status_code"`
	Headers     http.Header            `json:"headers"`
	Body        interface{}            `json:"body"`
	Error       string                 `json:"error,omitempty"`
	Duration    time.Duration          `json:"duration"`
	RequestID   string                 `json:"request_id"`
	RetryCount  int                    `json:"retry_count"`
}

/*
MAIN FUNCTION
Entry point for the HTTP client demonstration
*/
func main() {
	// Print startup banner
	fmt.Println("🚀 Starting Scholastic Go Tutorial HTTP Client...")
	fmt.Println("📡 Connecting to server and demonstrating Go concepts!")
	fmt.Println(strings.Repeat("=", 60))

	/*
	CLIENT CONFIGURATION
	Create and configure the HTTP client with various settings
	This demonstrates Go's approach to configuration and dependency injection
	*/
	config := &ClientConfig{
		BaseURL:     "http://localhost:8080", // Default server URL
		Timeout:     15 * time.Second,        // Request timeout
		MaxRetries:  3,                       // Maximum retry attempts
		RetryDelay:  1 * time.Second,         // Delay between retries
		UserAgent:   "ScholasticGoClient/1.0", // Custom User-Agent
		AuthToken:   "demo_token_123",        // Demo authentication token
		Debug:       true,                    // Enable debug logging
		MaxWorkers:  5,                       // Maximum concurrent workers
		BufferSize:  100,                     // Channel buffer size
	}

	// Create HTTP client with custom configuration
	client := NewHTTPClient(config)
	
	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	/*
	SIGNAL HANDLING
	Set up signal handling for graceful shutdown
	This demonstrates Go's approach to handling system signals
	*/
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	/*
	CONCURRENT DEMONSTRATIONS
	Run multiple demonstrations concurrently to show Go's concurrency features
	*/
	var wg sync.WaitGroup
	
	/*
	CHANNELS FOR COMMUNICATION
	Create channels for coordinating between goroutines
	This demonstrates Go's channel-based communication pattern
	*/
	resultsChan := make(chan string, config.BufferSize)
	errorsChan := make(chan error, config.BufferSize)
	doneChan := make(chan bool, 1)

	/*
	GOROUTINE 1: BASIC HTTP REQUESTS
	Demonstrate basic HTTP client operations
	*/
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Println("🔄 Starting basic HTTP requests demonstration...")
		
		// Health check request
		if err := demonstrateHealthCheck(client, resultsChan); err != nil {
			errorsChan <- fmt.Errorf("health check failed: %w", err)
		}
		
		// Get users request
		if err := demonstrateGetUsers(client, resultsChan); err != nil {
			errorsChan <- fmt.Errorf("get users failed: %w", err)
		}
		
		// Create user request
		if err := demonstrateCreateUser(client, resultsChan); err != nil {
			errorsChan <- fmt.Errorf("create user failed: %w", err)
		}
		
		resultsChan <- "✅ Basic HTTP requests demonstration completed"
	}()

	/*
	GOROUTINE 2: CONCURRENT REQUESTS
	Demonstrate concurrent HTTP requests using goroutines
	*/
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Println("🔄 Starting concurrent requests demonstration...")
		
		if err := demonstrateConcurrentRequests(client, config, resultsChan); err != nil {
			errorsChan <- fmt.Errorf("concurrent requests failed: %w", err)
		}
		
		resultsChan <- "✅ Concurrent requests demonstration completed"
	}()

	/*
	GOROUTINE 3: CALCULATION REQUESTS
	Demonstrate mathematical operations via API
	*/
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Println("🔄 Starting calculation requests demonstration...")
		
		if err := demonstrateCalculations(client, resultsChan); err != nil {
			errorsChan <- fmt.Errorf("calculations failed: %w", err)
		}
		
		resultsChan <- "✅ Calculation requests demonstration completed"
	}()

	/*
	GOROUTINE 4: GOROUTINE DEMONSTRATION
	Demonstrate goroutine patterns via API
	*/
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Println("🔄 Starting goroutine demonstration via API...")
		
		if err := demonstrateGoroutineAPI(client, resultsChan); err != nil {
			errorsChan <- fmt.Errorf("goroutine API failed: %w", err)
		}
		
		resultsChan <- "✅ Goroutine API demonstration completed"
	}()

	/*
	GOROUTINE 5: ERROR HANDLING DEMONSTRATION
	Demonstrate error handling and retry logic
	*/
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Println("🔄 Starting error handling demonstration...")
		
		if err := demonstrateErrorHandling(client, resultsChan); err != nil {
			errorsChan <- fmt.Errorf("error handling demo failed: %w", err)
		}
		
		resultsChan <- "✅ Error handling demonstration completed"
	}()

	/*
	GOROUTINE 6: WEBSOCKET SIMULATION
	Demonstrate WebSocket-like communication
	*/
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Println("🔄 Starting WebSocket simulation...")
		
		if err := demonstrateWebSocketSimulation(client, resultsChan); err != nil {
			errorsChan <- fmt.Errorf("WebSocket simulation failed: %w", err)
		}
		
		resultsChan <- "✅ WebSocket simulation completed"
	}()

	/*
	RESULT COLLECTION GOROUTINE
	Collect and display results from all demonstrations
	*/
	go func() {
		completed := 0
		total := 6 // Number of demonstration goroutines
		
		for {
			select {
			case result := <-resultsChan:
				log.Printf("📊 RESULT: %s", result)
				completed++
				
				if completed >= total {
					log.Printf("🎉 All demonstrations completed! (%d/%d)", completed, total)
					doneChan <- true
					return
				}
				
			case err := <-errorsChan:
				log.Printf("❌ ERROR: %v", err)
				
			case <-ctx.Done():
				log.Println("⏹️  Result collection cancelled")
				return
				
			case <-time.After(30 * time.Second):
				log.Printf("⚠️  Timeout: Only %d/%d demonstrations completed", completed, total)
				doneChan <- true
				return
			}
		}
	}()

	/*
	MAIN GOROUTINE WAITING
	Wait for either completion or shutdown signal
	*/
	select {
	case <-doneChan:
		log.Println("🎉 All demonstrations completed successfully!")
		
	case <-sigChan:
		log.Println("🛑 Shutdown signal received, cancelling demonstrations...")
		cancel() // Cancel context to stop all goroutines
		
	case <-time.After(45 * time.Second):
		log.Println("⏰ Overall timeout reached, cancelling demonstrations...")
		cancel()
	}

	/*
	WAIT FOR GOROUTINES TO COMPLETE
	Ensure all goroutines finish before exiting
	*/
	log.Println("⏳ Waiting for all goroutines to complete...")
	wg.Wait()
	
	log.Println("👋 Client demonstration completed. Goodbye!")
}

/*
NEWHTTPCLIENT FUNCTION
Creates a new HTTP client with custom configuration
*/
func NewHTTPClient(config *ClientConfig) *HTTPClient {
	// Create HTTP transport with custom settings
	transport := &http.Transport{
		MaxIdleConns:        100,              // Maximum idle connections
		MaxIdleConnsPerHost: 10,               // Maximum idle connections per host
		IdleConnTimeout:     90 * time.Second, // Idle connection timeout
		DisableCompression:  false,            // Enable compression
	}

	// Create HTTP client with custom timeout and transport
	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	return &HTTPClient{
		client:    client,
		config:    config,
		baseURL:   config.BaseURL,
		authToken: config.AuthToken,
		debug:     config.Debug,
		userAgent: config.UserAgent,
	}
}

/*
DEMONSTRATION FUNCTIONS
Each function demonstrates specific Go concepts and HTTP client patterns
*/

// demonstrateHealthCheck demonstrates basic HTTP GET request
func demonstrateHealthCheck(client *HTTPClient, resultsChan chan<- string) error {
	log.Println("🔍 Performing health check...")
	
	// Create request with context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Create GET request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, 
		fmt.Sprintf("%s/health", client.baseURL), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	// Add headers
	req.Header.Set("User-Agent", client.userAgent)
	req.Header.Set("Accept", "application/json")
	
	// Execute request with retry logic
	resp, err := client.executeWithRetry(req, 3)
	if err != nil {
		return fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()
	
	// Parse response
	var response models.SuccessResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	
	// Validate response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed with status: %d", resp.StatusCode)
	}
	
	resultsChan <- fmt.Sprintf("🏥 Health check passed: %s", response.Message)
	return nil
}

// demonstrateGetUsers demonstrates GET request with query parameters
func demonstrateGetUsers(client *HTTPClient, resultsChan chan<- string) error {
	log.Println("👥 Fetching users...")
	
	// Create request with query parameters
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Build URL with query parameters
	url := fmt.Sprintf("%s/api/users", client.baseURL)
	
	// Create GET request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	// Add headers
	req.Header.Set("User-Agent", client.userAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", client.authToken))
	
	// Execute request
	resp, err := client.executeWithRetry(req, 3)
	if err != nil {
		return fmt.Errorf("get users request failed: %w", err)
	}
	defer resp.Body.Close()
	
	// Parse response
	var response models.SuccessResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	
	// Extract users data
	usersData, ok := response.Data.([]interface{})
	if !ok {
		return fmt.Errorf("unexpected response format")
	}
	
	resultsChan <- fmt.Sprintf("👥 Retrieved %d users", len(usersData))
	return nil
}

// demonstrateCreateUser demonstrates POST request with JSON body
func demonstrateCreateUser(client *HTTPClient, resultsChan chan<- string) error {
	log.Println("➕ Creating new user...")
	
	// Create user data
	newUser := models.User{
		Username:  "demo_client_user",
		Email:     "demo@client.com",
		FirstName: "Demo",
		LastName:  "Client",
		Age:       25,
		Active:    true,
		Roles:     []string{"user", "demo"},
	}
	
	// Marshal user data to JSON
	userJSON, err := json.Marshal(newUser)
	if err != nil {
		return fmt.Errorf("failed to marshal user data: %w", err)
	}
	
	// Create request with context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Create POST request with JSON body
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, 
		fmt.Sprintf("%s/api/users", client.baseURL), bytes.NewBuffer(userJSON))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	// Add headers
	req.Header.Set("User-Agent", client.userAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", client.authToken))
	
	// Execute request
	resp, err := client.executeWithRetry(req, 3)
	if err != nil {
		return fmt.Errorf("create user request failed: %w", err)
	}
	defer resp.Body.Close()
	
	// Parse response
	var response models.SuccessResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	
	resultsChan <- fmt.Sprintf("➕ User created successfully: %s", response.Message)
	return nil
}

// demonstrateConcurrentRequests demonstrates concurrent HTTP requests
func demonstrateConcurrentRequests(client *HTTPClient, config *ClientConfig, resultsChan chan<- string) error {
	log.Printf("🔄 Executing %d concurrent requests...", config.MaxWorkers*2)
	
	// Create channels for coordination
	requestsChan := make(chan string, config.MaxWorkers*2)
	results := make([]string, 0)
	resultsMutex := sync.Mutex{}
	
	var wg sync.WaitGroup
	
	// Start worker goroutines
	for i := 0; i < config.MaxWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			for endpoint := range requestsChan {
				// Make concurrent request
				if err := makeConcurrentRequest(client, endpoint, workerID, &resultsMutex, &results); err != nil {
					log.Printf("❌ Worker %d request failed: %v", workerID, err)
				} else {
					log.Printf("✅ Worker %d completed request to %s", workerID, endpoint)
				}
			}
		}(i)
	}
	
	// Send requests to workers
	endpoints := []string{
		"/health",
		"/api/users",
		"/health",
		"/api/users",
		"/health",
		"/api/users",
		"/health",
		"/api/users",
		"/health",
		"/api/users",
	}
	
	for _, endpoint := range endpoints {
		requestsChan <- endpoint
	}
	close(requestsChan)
	
	// Wait for all workers to complete
	wg.Wait()
	
	resultsChan <- fmt.Sprintf("🔄 Completed %d concurrent requests", len(results))
	return nil
}

// makeConcurrentRequest makes a single HTTP request (used by concurrent demo)
func makeConcurrentRequest(client *HTTPClient, endpoint string, workerID int, 
	resultsMutex *sync.Mutex, results *[]string) error {
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, 
		fmt.Sprintf("%s%s", client.baseURL, endpoint), nil)
	if err != nil {
		return err
	}
	
	req.Header.Set("User-Agent", client.userAgent)
	req.Header.Set("Accept", "application/json")
	
	resp, err := client.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	// Add result to shared slice (with mutex protection)
	resultsMutex.Lock()
	*results = append(*results, fmt.Sprintf("Worker %d: %s", workerID, endpoint))
	resultsMutex.Unlock()
	
	return nil
}

// demonstrateCalculations demonstrates mathematical operations via API
func demonstrateCalculations(client *HTTPClient, resultsChan chan<- string) error {
	log.Println("🧮 Performing mathematical calculations...")
	
	// Define calculation requests
	calculations := []struct {
		operation string
		a, b      float64
		precision int
	}{
		{"add", 10.5, 20.3, 2},
		{"subtract", 100, 45.5, 2},
		{"multiply", 7, 8, 2},
		{"divide", 100, 4, 2},
		{"power", 2, 8, 2},
	}
	
	// Perform calculations sequentially (for demonstration)
	for _, calc := range calculations {
		calcRequest := models.CalculationRequest{
			Operation: calc.operation,
			A:         calc.a,
			B:         calc.b,
			Precision: calc.precision,
		}
		
		// Marshal calculation data
		calcJSON, err := json.Marshal(calcRequest)
		if err != nil {
			return fmt.Errorf("failed to marshal calculation: %w", err)
		}
		
		// Create request
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, 
			fmt.Sprintf("%s/api/calculate", client.baseURL), bytes.NewBuffer(calcJSON))
		if err != nil {
			cancel()
			return fmt.Errorf("failed to create request: %w", err)
		}
		
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		
		// Execute request
		resp, err := client.executeWithRetry(req, 3)
		cancel()
		if err != nil {
			return fmt.Errorf("calculation request failed: %w", err)
		}
		resp.Body.Close()
		
		log.Printf("🧮 Completed calculation: %s(%.1f, %.1f)", 
			calc.operation, calc.a, calc.b)
	}
	
	resultsChan <- fmt.Sprintf("🧮 Completed %d mathematical calculations", len(calculations))
	return nil
}

// demonstrateGoroutineAPI demonstrates goroutine patterns via API
func demonstrateGoroutineAPI(client *HTTPClient, resultsChan chan<- string) error {
	log.Println("🦍 Demonstrating goroutine patterns via API...")
	
	// Create goroutine demonstration request
	goroutineRequest := models.GoroutineRequest{
		TaskType:    "basic",
		TaskCount:   10,
		DelayMs:     100,
		Description: "Client-side goroutine demonstration",
	}
	
	// Marshal request data
	requestJSON, err := json.Marshal(goroutineRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal goroutine request: %w", err)
	}
	
	// Create request
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, 
		fmt.Sprintf("%s/api/goroutines", client.baseURL), bytes.NewBuffer(requestJSON))
	if err != nil {
		cancel()
		return fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	
	// Execute request
	resp, err := client.executeWithRetry(req, 3)
	cancel()
	if err != nil {
		return fmt.Errorf("goroutine API request failed: %w", err)
	}
	defer resp.Body.Close()
	
	// Parse response
	var response models.SuccessResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	
	resultsChan <- "🦍 Goroutine API demonstration completed successfully"
	return nil
}

// demonstrateErrorHandling demonstrates error handling and retry logic
func demonstrateErrorHandling(client *HTTPClient, resultsChan chan<- string) error {
	log.Println("🚨 Demonstrating error handling...")
	
	// Test 1: Invalid endpoint (should fail)
	if err := testInvalidEndpoint(client); err != nil {
		log.Printf("✅ Expected error for invalid endpoint: %v", err)
	}
	
	// Test 2: Invalid request data (should fail)
	if err := testInvalidRequestData(client); err != nil {
		log.Printf("✅ Expected error for invalid data: %v", err)
	}
	
	// Test 3: Timeout handling
	if err := testTimeoutHandling(client); err != nil {
		log.Printf("✅ Expected timeout error: %v", err)
	}
	
	resultsChan <- "🚨 Error handling demonstration completed"
	return nil
}

// testInvalidEndpoint tests error handling for invalid endpoints
func testInvalidEndpoint(client *HTTPClient) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, 
		fmt.Sprintf("%s/invalid/endpoint", client.baseURL), nil)
	if err != nil {
		return err
	}
	
	req.Header.Set("Accept", "application/json")
	
	resp, err := client.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("expected 404, got %d", resp.StatusCode)
	}
	
	return nil // Expected behavior
}

// testInvalidRequestData tests error handling for invalid request data
func testInvalidRequestData(client *HTTPClient) error {
	// Create invalid user data (missing required fields)
	invalidData := map[string]interface{}{
		"username": "", // Empty username should fail validation
		"email":    "invalid-email", // Invalid email format
	}
	
	invalidJSON, err := json.Marshal(invalidData)
	if err != nil {
		return err
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, 
		fmt.Sprintf("%s/api/users", client.baseURL), bytes.NewBuffer(invalidJSON))
	if err != nil {
		return err
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	
	resp, err := client.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusBadRequest {
		return fmt.Errorf("expected 400, got %d", resp.StatusCode)
	}
	
	return nil // Expected behavior
}

// testTimeoutHandling tests timeout error handling
func testTimeoutHandling(client *HTTPClient) error {
	// Create context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, 
		fmt.Sprintf("%s/api/users", client.baseURL), nil)
	if err != nil {
		return err
	}
	
	// This should timeout immediately
	_, err = client.client.Do(req)
	if err != nil {
		return err // Expected timeout error
	}
	
	return fmt.Errorf("expected timeout error, but request succeeded")
}

// demonstrateWebSocketSimulation demonstrates WebSocket-like communication
func demonstrateWebSocketSimulation(client *HTTPClient, resultsChan chan<- string) error {
	log.Println("🔌 Simulating WebSocket communication...")
	
	// Test getting connected users
	if err := testGetConnectedUsers(client); err != nil {
		return err
	}
	
	// Test broadcasting a message
	if err := testBroadcastMessage(client); err != nil {
		return err
	}
	
	resultsChan <- "🔌 WebSocket simulation completed"
	return nil
}

// testGetConnectedUsers tests getting connected WebSocket users
func testGetConnectedUsers(client *HTTPClient) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, 
		fmt.Sprintf("%s/ws", client.baseURL), nil)
	if err != nil {
		return err
	}
	
	req.Header.Set("Accept", "application/json")
	
	resp, err := client.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	return nil
}

// testBroadcastMessage tests broadcasting a WebSocket message
func testBroadcastMessage(client *HTTPClient) error {
	message := models.WSMessage{
		Type:      "broadcast",
		From:      "demo_client",
		Content:   json.RawMessage(`{"text": "Hello from client!"}`),
		Timestamp: time.Now().Unix(),
	}
	
	messageJSON, err := json.Marshal(message)
	if err != nil {
		return err
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, 
		fmt.Sprintf("%s/ws", client.baseURL), bytes.NewBuffer(messageJSON))
	if err != nil {
		return err
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	
	resp, err := client.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	return nil
}

/*
CLIENT UTILITY METHODS
Additional methods for the HTTP client
*/

// executeWithRetry executes an HTTP request with retry logic
func (c *HTTPClient) executeWithRetry(req *http.Request, maxRetries int) (*http.Response, error) {
	var lastErr error
	
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retry (exponential backoff)
			delay := time.Duration(attempt) * c.config.RetryDelay
			log.Printf("🔄 Retry attempt %d after %v delay...", attempt, delay)
			time.Sleep(delay)
		}
		
		// Execute request
		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = err
			log.Printf("❌ Request attempt %d failed: %v", attempt+1, err)
			continue
		}
		
		// Check if response indicates success
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		}
		
		// Close response body for retry
		resp.Body.Close()
		
		// Check if error is retryable
		if !isRetryableStatus(resp.StatusCode) {
			return resp, fmt.Errorf("non-retryable status code: %d", resp.StatusCode)
		}
		
		lastErr = fmt.Errorf("status code: %d", resp.StatusCode)
		log.Printf("⚠️  Request attempt %d returned status %d", attempt+1, resp.StatusCode)
	}
	
	return nil, fmt.Errorf("all retry attempts failed, last error: %w", lastErr)
}

// isRetryableStatus determines if a status code is worth retrying
func isRetryableStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusRequestTimeout,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}
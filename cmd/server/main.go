// cmd/server/main.go - Entry point for our HTTP server
// This file demonstrates the main function structure and server initialization
// It serves as the starting point for understanding Go's execution model

package main

import (
	// Standard library imports organized by functionality
	"context"    // Context package for request lifecycle management
	"fmt"        // Formatted I/O operations
	"log"        // Logging functionality
	"net/http"   // HTTP server and client implementations
	"os"         // OS interface for system calls
	"os/signal"  // Signal handling for graceful shutdown
	"strings"    // String manipulation
	"syscall"    // System call constants
	"time"       // Time manipulation and measurement

	// Internal package imports - our custom packages
	"scholastic-go-tutorial/internal/config"    // Configuration management
	"scholastic-go-tutorial/internal/handlers"  // HTTP request handlers
	"scholastic-go-tutorial/internal/middleware" // HTTP middleware components
	"scholastic-go-tutorial/internal/services"  // Business logic services
)

/*
MAIN FUNCTION - Entry point of the Go program
Every Go program execution starts with the main() function in package main
This function demonstrates:
1. Configuration loading
2. Dependency injection
3. Server setup with middleware
4. Graceful shutdown handling
5. Signal handling for clean termination
*/
func main() {
	// Print startup banner with project information
	fmt.Println("🚀 Starting Scholastic Go Tutorial Server...")
	fmt.Println("📚 Learning Go through practical examples!")
	fmt.Println(strings.Repeat("=", 50))

	/*
	CONFIGURATION LOADING
	Load application configuration from environment variables and config files
	This demonstrates Go's approach to configuration management
	*/
	config, err := config.LoadConfig() // LoadConfig returns Config struct and error
	if err != nil {
		// Log fatal error and exit if configuration fails
		// log.Fatalf prints to stderr and calls os.Exit(1)
		log.Fatalf("❌ Failed to load configuration: %v", err)
	}

	// Log successful configuration loading with server details
	log.Printf("✅ Configuration loaded successfully")
	log.Printf("🌐 Server will listen on port: %s", config.ServerPort)
	log.Printf("📊 Debug mode: %t", config.DebugMode)

	/*
	SERVICE INITIALIZATION
	Create service instances with dependency injection
	This demonstrates Go's composition over inheritance approach
	*/
	// Initialize user service
	userService := services.NewUserService(nil)
	
	// Initialize math service for calculation examples
	mathService := services.NewMathService()
	
	// Initialize websocket service for real-time communication
	wsService := services.NewWebSocketService()

	/*
	HANDLER INITIALIZATION
	Create HTTP handlers with injected services
	Handlers are responsible for processing HTTP requests and responses
	*/
	// API handler group - handles REST API endpoints
	apiHandler := handlers.NewAPIHandler(userService, mathService)
	
	// WebSocket handler for real-time communication
	wsHandler := handlers.NewWebSocketHandler(wsService)
	
	// Static file handler for serving HTML, CSS, JS files
	staticHandler := handlers.NewStaticHandler("./web")

	/*
	MUX (HTTP ROUTER) SETUP
	Create and configure HTTP request multiplexer
	The ServeMux matches incoming requests against a list of registered patterns
	and calls the handler for the pattern that most closely matches the URL
	*/
	mux := http.NewServeMux()

	/*
	ROUTE REGISTRATION
	Register URL patterns with their corresponding handlers
	Order matters - more specific patterns should come before generic ones
	*/
	// Health check endpoint - simple endpoint to verify server is running
	mux.HandleFunc("/health", apiHandler.HealthCheck)
	
	// REST API endpoints for CRUD operations
	mux.HandleFunc("/api/users", apiHandler.UsersHandler)           // GET all users, POST new user
	mux.HandleFunc("/api/users/", apiHandler.UserHandler)           // GET specific user, PUT update, DELETE
	mux.HandleFunc("/api/calculate", apiHandler.CalculateHandler)   // Math calculation examples
	mux.HandleFunc("/api/goroutines", apiHandler.GoroutineHandler)  // Goroutine demonstration
	
	// WebSocket endpoint for real-time communication
	mux.HandleFunc("/ws", wsHandler.HandleWebSocket)
	
	// Static file serving - serves files from ./web directory
	mux.Handle("/", staticHandler)

	/*
	MIDDLEWARE CHAIN CONSTRUCTION
	Wrap the main mux with middleware functions
	Middleware functions are executed in the order they are applied (outer to inner)
	Each middleware can modify the request/response before passing to the next handler
	*/
	// Apply middleware chain: Logging -> Recovery -> CORS -> Main Handler
	handler := middleware.LoggingMiddleware(                    // Log all incoming requests
		middleware.RecoveryMiddleware(                          // Recover from panics
			middleware.CORSMiddleware(                        // Add CORS headers
				middleware.RequestIDMiddleware(mux), // Add unique request ID
			),
		),
	)

	/*
	HTTP SERVER CREATION
	Create HTTP server with custom configuration
	This demonstrates fine-grained control over server behavior
	*/
	server := &http.Server{
		Addr:         ":" + config.ServerPort, // Listen address with port
		Handler:      handler,                 // Request handler (with middleware chain)
		ReadTimeout:  15 * time.Second,        // Maximum duration for reading request
		WriteTimeout: 15 * time.Second,        // Maximum duration for writing response
		IdleTimeout:  60 * time.Second,        // Maximum idle time between requests
	}

	/*
	GRACEFUL SHUTDOWN SETUP
	Create channel to listen for interrupt signals
	This allows the server to shut down cleanly without losing in-flight requests
	*/
	// Create channel to receive OS signals
	shutdown := make(chan os.Signal, 1)
	
	// Register interested signals: SIGINT (Ctrl+C) and SIGTERM (termination)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	/*
	SERVER STARTUP IN GOROUTINE
	Start server in separate goroutine to allow main goroutine to handle shutdown
	This demonstrates Go's concurrency model and goroutine usage
	*/
	go func() {
		log.Printf("🌐 Starting HTTP server on http://localhost%s", server.Addr)
		log.Println("📖 Ready to teach Go concepts!")
		log.Println(strings.Repeat("=", 50))

		// ListenAndServe blocks until server is shut down or encounters an error
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Log fatal error if server fails to start (not a graceful shutdown)
			log.Fatalf("❌ Server failed to start: %v", err)
		}
	}()

	/*
	MAIN GOROUTINE BLOCKING
	Wait for shutdown signal in main goroutine
	This keeps the program running until termination is requested
	*/
	log.Println("⏳ Server is running. Press Ctrl+C to stop.")
	
	// Block until shutdown signal is received
	sig := <-shutdown
	
	// Log received signal
	log.Printf("🛑 Received signal: %v", sig)
	log.Println("🔄 Initiating graceful shutdown...")

	/*
	GRACEFUL SHUTDOWN EXECUTION
	Create context with timeout for shutdown operations
	Context provides deadline/cancellation signals across API boundaries
	*/
	// Create context with 30-second timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel() // Always call cancel to release resources

	/*
	SHUTDOWN SEQUENCE
	Attempt to gracefully shutdown the server
	This includes:
	1. Stop accepting new connections
	2. Wait for existing connections to finish
	3. Close all resources
	*/
	if err := server.Shutdown(ctx); err != nil {
		// Log error if graceful shutdown fails
		log.Printf("❌ Graceful shutdown failed: %v", err)
		
		// Force shutdown by closing the server
		if err := server.Close(); err != nil {
			log.Printf("❌ Force shutdown failed: %v", err)
		}
	}

	/*
	CLEANUP AND TERMINATION
	Perform any final cleanup operations
	This is where you would close database connections, file handles, etc.
	*/
	log.Println("✅ Server shutdown complete")
	log.Println("👋 Thank you for using Scholastic Go Tutorial!")
}
# Go Application Lifecycle and Flow

This document explains how the Scholastic Go Tutorial application starts, loads, and executes using proper Go terminology and concepts.

## Table of Contents

1. [Go Module System](#go-module-system)
2. [Application Entry Points](#application-entry-points)
3. [Server Application Flow](#server-application-flow)
4. [Client Application Flow](#client-application-flow)
5. [Package Initialization](#package-initialization)
6. [HTTP Server Lifecycle](#http-server-lifecycle)
7. [Concurrency Patterns](#concurrency-patterns)
8. [Middleware Chain](#middleware-chain)
9. [Configuration Loading](#configuration-loading)

## Go Module System

### Module Initialization

The application starts with the `go.mod` file, which defines the Go module:

```go
module scholastic-go-tutorial

go 1.21
```

**Key Concepts:**
- **Module**: A collection of Go packages stored in a file tree with a `go.mod` file at its root
- **Module Path**: The import path prefix for all packages within the module
- **Go Version**: Specifies the minimum Go version required for the module

### Dependency Resolution

When the application runs, Go performs these steps:

1. **Module Discovery**: Go reads `go.mod` to understand the module structure
2. **Import Path Resolution**: Go resolves import paths to locate packages
3. **Vendor Directory**: If present, Go uses the vendor directory for dependencies
4. **Module Cache**: Go caches downloaded modules in `$GOPATH/pkg/mod`

## Application Entry Points

### Go Execution Model

Go applications follow this execution model:

1. **Package `main`**: The entry point must be in a package named `main`
2. **`func main()`**: The main function is the application entry point
3. **Initialization Order**: 
   - Package-level variables are initialized first
   - `init()` functions are executed in declaration order
   - `main()` function is called last

### Entry Points in This Project

The project has two main entry points:

#### Server Entry Point: `cmd/server/main.go`

```go
package main

func main() {
    // Server initialization code
}
```

#### Client Entry Point: `cmd/client/main.go`

```go
package main

func main() {
    // Client initialization code
}
```

## Server Application Flow

### 1. Package Initialization

When you run `go run cmd/server/main.go`, Go executes in this order:

1. **Import Resolution**: Go resolves all import statements
2. **Package Variables**: All package-level variables are initialized
3. **`init()` Functions**: Any `init()` functions are executed
4. **`main()` Function**: The main function is executed

### 2. Main Function Execution

```go
func main() {
    // 1. Configuration loading
    config, err := config.LoadConfig()
    
    // 2. Dependencies initialization
    userService := services.NewUserService(config)
    
    // 3. HTTP handlers setup
    userHandler := handlers.NewUserHandler(userService)
    
    // 4. Middleware chain setup
    router := setupRouter(config, userHandler)
    
    // 5. Server creation and start
    server := &http.Server{
        Addr:    ":" + config.Port,
        Handler: router,
    }
    
    // 6. Graceful shutdown setup
    setupGracefulShutdown(server)
    
    // 7. Server start
    log.Printf("Server starting on port %s", config.Port)
    if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
        log.Fatalf("Server failed to start: %v", err)
    }
}
```

### 3. Package Dependency Graph

```
main (cmd/server/main.go)
├── config (internal/config/config.go)
├── services (internal/services/services.go)
├── handlers (internal/handlers/handlers.go)
├── middleware (internal/middleware/middleware.go)
├── models (internal/models/models.go)
└── web (web/index.html)
```

## Client Application Flow

### 1. Client Initialization

```go
func main() {
    // 1. Configuration loading
    config, err := config.LoadConfig()
    
    // 2. HTTP client setup
    httpClient := &http.Client{
        Timeout: time.Second * 10,
    }
    
    // 3. Service client creation
    userClient := services.NewUserClient(httpClient, config)
    
    // 4. Execute client demonstrations
    runClientDemos(userClient)
}
```

### 2. Concurrent Request Processing

```go
func runClientDemos(client *services.UserClient) {
    // Create a channel for results
    results := make(chan *models.User, 10)
    
    // Create a worker pool
    for i := 0; i < 5; i++ {
        go worker(i, client, results)
    }
    
    // Process results
    for result := range results {
        fmt.Printf("Processed user: %s\n", result.Name)
    }
}
```

## Package Initialization

### Package Loading Order

Go loads packages in this order:

1. **Standard Library**: Built-in packages (`fmt`, `net/http`, etc.)
2. **Third-Party Packages**: External dependencies
3. **Internal Packages**: Project-specific packages
4. **Main Package**: The entry point package

### Initialization Example

For each package, Go executes:

```go
package handlers

// 1. Package-level variables are initialized first
var DefaultUserHandler *UserHandler

// 2. init() functions are executed in declaration order
func init() {
    DefaultUserHandler = &UserHandler{}
}

// 3. Functions and types are available after initialization
type UserHandler struct {
    userService services.UserService
}
```

## HTTP Server Lifecycle

### 1. Server Creation

```go
// Create HTTP server instance
server := &http.Server{
    Addr:         ":8080",
    Handler:      router,
    ReadTimeout:  10 * time.Second,
    WriteTimeout: 10 * time.Second,
}
```

### 2. Router Setup

```go
func setupRouter(config *config.Config, userHandler *handlers.UserHandler) *mux.Router {
    // Create router instance
    router := mux.NewRouter()
    
    // Apply middleware chain
    router.Use(middleware.Logging)
    router.Use(middleware.CORS)
    router.Use(middleware.Recovery)
    router.Use(middleware.RequestID)
    router.Use(middleware.Authentication)
    
    // Register routes
    router.HandleFunc("/health", handlers.HealthCheck).Methods("GET")
    router.HandleFunc("/api/users", userHandler.GetUsers).Methods("GET")
    router.HandleFunc("/api/users", userHandler.CreateUser).Methods("POST")
    
    return router
}
```

### 3. Request Processing Lifecycle

```
Incoming Request → Middleware Chain → Handler → Response
                    ↓
          [Logging → CORS → Recovery → RequestID → Auth]
```

### 4. Graceful Shutdown

```go
func setupGracefulShutdown(server *http.Server) {
    // Create channel for shutdown signals
    quit := make(chan os.Signal, 1)
    
    // Register signal handlers
    signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
    
    // Wait for shutdown signal
    <-quit
    
    // Create context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    // Graceful shutdown
    if err := server.Shutdown(ctx); err != nil {
        log.Printf("Server shutdown error: %v", err)
    }
    
    log.Println("Server stopped")
}
```

## Concurrency Patterns

### 1. Goroutine Lifecycle

```go
// Goroutine creation
go func() {
    // Goroutine execution
    defer wg.Done() // Signal completion
    
    // Process data
    result := processData(data)
    
    // Send result through channel
    results <- result
}()
```

### 2. Channel Communication

```go
// Buffered channel creation
tasks := make(chan *models.Task, 100)
results := make(chan *models.Result, 100)

// Producer pattern
go func() {
    for _, task := range taskList {
        tasks <- task
    }
    close(tasks)
}()

// Consumer pattern (worker pool)
for i := 0; i < numWorkers; i++ {
    go worker(i, tasks, results)
}
```

### 3. WaitGroup Synchronization

```go
// WaitGroup for goroutine synchronization
var wg sync.WaitGroup

// Add goroutines to wait group
for i := 0; i < numGoroutines; i++ {
    wg.Add(1)
    go func(id int) {
        defer wg.Done()
        // Goroutine work
        processItem(id)
    }(i)
}

// Wait for all goroutines to complete
wg.Wait()
```

## Middleware Chain

### 1. Middleware Pattern

```go
// Middleware type definition
type Middleware func(http.Handler) http.Handler

// Middleware application
func Logging(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        
        // Call next handler
        next.ServeHTTP(w, r)
        
        // Log after request processing
        log.Printf("%s %s %v", r.Method, r.URL.Path, time.Since(start))
    })
}
```

### 2. Chain Execution

```go
// Middleware chain execution
func (m *MiddlewareChain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // Execute middleware in order
    for _, mw := range m.middlewares {
        r = mw.Process(r)
    }
    
    // Call final handler
    m.handler.ServeHTTP(w, r)
}
```

### 3. Context Propagation

```go
// Request ID middleware
func RequestID(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Generate request ID
        requestID := generateRequestID()
        
        // Add request ID to context
        ctx := context.WithValue(r.Context(), "requestID", requestID)
        
        // Create new request with context
        r = r.WithContext(ctx)
        
        // Call next handler
        next.ServeHTTP(w, r)
    })
}
```

## Configuration Loading

### 1. Environment Variable Loading

```go
func LoadConfig() (*Config, error) {
    config := &Config{
        // Load from environment variables
        Port:     getEnv("PORT", "8080"),
        Database: getEnv("DATABASE_URL", ""),
        LogLevel: getEnv("LOG_LEVEL", "info"),
    }
    
    // Validate configuration
    if err := config.Validate(); err != nil {
        return nil, fmt.Errorf("configuration validation failed: %w", err)
    }
    
    return config, nil
}
```

### 2. Configuration Validation

```go
func (c *Config) Validate() error {
    // Validate port
    if _, err := strconv.Atoi(c.Port); err != nil {
        return fmt.Errorf("invalid port: %s", c.Port)
    }
    
    // Validate database URL
    if c.Database == "" {
        return fmt.Errorf("database URL is required")
    }
    
    // Validate log level
    validLevels := map[string]bool{
        "debug": true, "info": true, "warn": true, "error": true,
    }
    if !validLevels[c.LogLevel] {
        return fmt.Errorf("invalid log level: %s", c.LogLevel)
    }
    
    return nil
}
```

### 3. Runtime Configuration Updates

```go
// Configuration watcher
func watchConfig(config *Config, done <-chan struct{}) {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            // Check for configuration changes
            if newConfig, err := LoadConfig(); err == nil {
                *config = *newConfig
                log.Println("Configuration reloaded")
            }
        case <-done:
            // Stop watching
            return
        }
    }
}
```

## Summary

This Go application demonstrates:

1. **Module System**: Proper Go module structure and dependency management
2. **Entry Points**: Clean separation of server and client entry points
3. **Package Organization**: Logical package structure with clear responsibilities
4. **HTTP Server**: Complete HTTP server with middleware and graceful shutdown
5. **Concurrency**: Goroutines, channels, and synchronization patterns
6. **Configuration**: Environment-based configuration with validation
7. **Error Handling**: Comprehensive error handling throughout the application
8. **Testing**: Testable code structure with dependency injection

The application follows Go best practices and idioms, making it an excellent learning resource for understanding Go application development patterns.
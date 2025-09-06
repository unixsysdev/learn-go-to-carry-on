# 🎓 Scholastic Go Tutorial

A comprehensive Go learning project that teaches Go programming concepts through a practical client-server HTTP application. Every line is commented to explain Go concepts, patterns, and best practices.

## 🌟 Project Overview

This project demonstrates real-world Go development patterns by building a complete HTTP server and client application. It covers essential Go concepts including:

- **HTTP Server/Client Architecture**: Complete REST API implementation
- **Concurrency**: Goroutines, channels, worker pools, and patterns
- **Interfaces and Structs**: Go's approach to abstraction and composition
- **Middleware**: HTTP middleware for cross-cutting concerns
- **Configuration Management**: Environment-based configuration with validation
- **Error Handling**: Go's explicit error handling patterns
- **Package Organization**: Professional Go project structure
- **Testing Patterns**: Unit testing and integration testing approaches

## 🏗️ Project Structure

```
scholastic-go-tutorial/
├── cmd/                    # Application entry points
│   ├── server/            # HTTP server main.go
│   └── client/            # HTTP client main.go
├── internal/              # Private application code
│   ├── config/           # Configuration management
│   ├── handlers/         # HTTP request handlers
│   ├── middleware/       # HTTP middleware components
│   ├── models/          # Data models and structures
│   └── services/        # Business logic services
├── web/                  # Static web interface
│   └── index.html       # Interactive tutorial interface
├── go.mod               # Go module definition
└── README.md           # This file
```

## 🚀 Quick Start

### Prerequisites

- Go 1.21 or higher
- Terminal/Command line access

### Installation and Setup

1. **Clone or create the project**:
   ```bash
   mkdir scholastic-go-tutorial
   cd scholastic-go-tutorial
   # Copy all the provided files into this directory
   ```

2. **Initialize Go module**:
   ```bash
   go mod tidy
   ```

3. **Start the server**:
   ```bash
   go run cmd/server/main.go
   ```

4. **In a new terminal, run the client**:
   ```bash
   go run cmd/client/main.go
   ```

5. **Access the web interface**:
   Open your browser to `http://localhost:8080` for an interactive tutorial interface.

## 📚 Learning Path

### 1. Server Architecture (`cmd/server/main.go`)

Start with the server main file to understand:
- Go program structure and the `main()` function
- HTTP server setup with `http.Server`
- Middleware chain implementation
- Graceful shutdown handling
- Service initialization and dependency injection

Key concepts demonstrated:
```go
// HTTP server creation with custom configuration
server := &http.Server{
    Addr:         ":8080",
    Handler:      handler,
    ReadTimeout:  15 * time.Second,
    WriteTimeout: 15 * time.Second,
}

// Graceful shutdown with signal handling
shutdown := make(chan os.Signal, 1)
signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
```

### 2. Configuration Management (`internal/config/config.go`)

Learn about:
- Struct-based configuration
- Environment variable handling
- Configuration validation
- Default values and type conversion

Key concepts demonstrated:
```go
// Configuration struct with validation
type Config struct {
    ServerPort  string        `json:"server_port"`
    DebugMode   bool          `json:"debug_mode"`
    Environment string        `json:"environment"`
}

// Configuration loading with validation
func LoadConfig() (*Config, error) {
    config := &Config{
        ServerPort: getEnvOrDefault("SERVER_PORT", "8080"),
        DebugMode:  getEnvBoolOrDefault("DEBUG_MODE", false),
    }
    
    if err := config.Validate(); err != nil {
        return nil, fmt.Errorf("validation failed: %w", err)
    }
    
    return config, nil
}
```

### 3. Data Models (`internal/models/models.go`)

Understand:
- Struct definition and JSON marshaling
- Interface implementation
- Validation patterns
- Custom marshaling

Key concepts demonstrated:
```go
// Struct with JSON tags and validation
type User struct {
    ID        int       `json:"id"`
    Username  string    `json:"username"`
    Email     string    `json:"email"`
    Active    bool      `json:"active"`
    CreatedAt time.Time `json:"created_at"`
}

// Interface for validation
type Validator interface {
    Validate() error
}

// Interface implementation
func (u *User) Validate() error {
    if strings.TrimSpace(u.Username) == "" {
        return fmt.Errorf("username cannot be empty")
    }
    // ... more validation
    return nil
}
```

### 4. Services Layer (`internal/services/services.go`)

Explore:
- Service interfaces and dependency injection
- Goroutine patterns and concurrency
- Mutex usage for thread safety
- Business logic separation

Key concepts demonstrated:
```go
// Service interface definition
type UserServiceInterface interface {
    GetUserByID(id int) (*models.User, error)
    CreateUser(user *models.User) error
}

// Service implementation with concurrency
func (s *UserService) GetUserByID(id int) (*models.User, error) {
    s.mu.RLock()         // Read lock for concurrent access
    defer s.mu.RUnlock()
    
    user, exists := s.users[id]
    if !exists {
        return nil, fmt.Errorf("user not found")
    }
    
    return user, nil
}

// Goroutine patterns
func (s *MathService) PerformBulkCalculations(requests []models.CalculationRequest) []CalculationResult {
    // Worker pool pattern demonstration
    resultsChan := make(chan struct {
        index int
        result CalculationResult
    }, len(requests))
    
    // Start worker goroutines
    for w := 0; w < maxWorkers; w++ {
        go func(workerID int) {
            // Worker implementation
        }(w)
    }
}
```

### 5. HTTP Handlers (`internal/handlers/handlers.go`)

Learn about:
- HTTP request routing and method handling
- Request body parsing and validation
- Response formatting and error handling
- RESTful API patterns

Key concepts demonstrated:
```go
// Handler struct with dependencies
type APIHandler struct {
    userService UserServiceInterface
    mathService MathServiceInterface
}

// HTTP method routing
func (h *APIHandler) UsersHandler(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        h.getUsers(w, r)
    case http.MethodPost:
        h.createUser(w, r)
    default:
        sendErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}

// Request parsing and validation
func (h *APIHandler) createUser(w http.ResponseWriter, r *http.Request) {
    var user models.User
    if err := parseJSONBody(r, &user); err != nil {
        sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    
    if err := user.ValidateCreate(); err != nil {
        sendErrorResponse(w, fmt.Sprintf("Validation failed: %v", err), http.StatusBadRequest)
        return
    }
}
```

### 6. HTTP Middleware (`internal/middleware/middleware.go`)

Understand:
- Middleware function patterns
- Request processing pipeline
- Cross-cutting concerns (logging, CORS, recovery)
- Middleware composition

Key concepts demonstrated:
```go
// Middleware function signature
func LoggingMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Pre-processing
        log.Printf("Request: %s %s", r.Method, r.URL.Path)
        
        // Call next handler
        next.ServeHTTP(w, r)
        
        // Post-processing
        log.Printf("Response completed")
    })
}

// Middleware composition
handler := RequestIDMiddleware(
    LoggingMiddleware(
        RecoveryMiddleware(
            CORSMiddleware(next),
        ),
    ),
)
```

### 7. HTTP Client (`cmd/client/main.go`)

Explore:
- HTTP client creation and configuration
- Concurrent request handling
- Retry logic and error handling
- Context usage for request lifecycle

Key concepts demonstrated:
```go
// HTTP client with custom configuration
type HTTPClient struct {
    client    *http.Client
    config    *ClientConfig
    baseURL   string
    authToken string
}

// Concurrent request handling
func demonstrateConcurrentRequests(client *HTTPClient, config *ClientConfig) error {
    var wg sync.WaitGroup
    requestsChan := make(chan string, config.BufferSize)
    
    // Start worker goroutines
    for i := 0; i < config.MaxWorkers; i++ {
        wg.Add(1)
        go func(workerID int) {
            defer wg.Done()
            
            for endpoint := range requestsChan {
                // Make concurrent request
                makeConcurrentRequest(client, endpoint, workerID)
            }
        }(i)
    }
    
    // Send requests and wait for completion
    // ...
    wg.Wait()
}

// Request with retry logic
func (c *HTTPClient) executeWithRetry(req *http.Request, maxRetries int) (*http.Response, error) {
    var lastErr error
    
    for attempt := 0; attempt <= maxRetries; attempt++ {
        if attempt > 0 {
            delay := time.Duration(attempt) * c.config.RetryDelay
            time.Sleep(delay)
        }
        
        resp, err := c.client.Do(req)
        if err != nil {
            lastErr = err
            continue
        }
        
        if resp.StatusCode >= 200 && resp.StatusCode < 300 {
            return resp, nil
        }
        
        resp.Body.Close()
        lastErr = fmt.Errorf("status code: %d", resp.StatusCode)
    }
    
    return nil, fmt.Errorf("all retry attempts failed: %w", lastErr)
}
```

## 🧪 API Endpoints

### Health Check
- `GET /health` - Server health status

### Users API
- `GET /api/users` - Get all users (with optional search)
- `POST /api/users` - Create new user
- `GET /api/users/{id}` - Get specific user
- `PUT /api/users/{id}` - Update user
- `DELETE /api/users/{id}` - Delete user

### Calculations API
- `POST /api/calculate` - Perform mathematical calculations
  - Operations: add, subtract, multiply, divide, power, sqrt, sin, cos, tan, log
  - Supports precision control

### Goroutines API
- `POST /api/goroutines` - Demonstrate goroutine patterns
  - Task types: basic, pipeline, worker_pool, fan_out_fan_in

### WebSocket Simulation
- `GET /ws` - Get connected users
- `POST /ws` - Send WebSocket message (broadcast/direct)

## 🔧 Environment Configuration

The server supports environment variable configuration:

```bash
# Server configuration
SERVER_PORT=8080
SERVER_HOST=localhost

# Application settings
DEBUG_MODE=true
ENVIRONMENT=development

# Database (for future expansion)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=scholastic_go
DB_USER=postgres
DB_PASSWORD=password

# WebSocket settings
WS_READ_BUFFER_SIZE=1024
WS_WRITE_BUFFER_SIZE=1024

# Security
ENABLE_CORS=true
ALLOWED_ORIGINS=*
ENABLE_RATE_LIMIT=false
RATE_LIMIT_RPS=10
```

## 🧪 Testing the Application

### Using the Web Interface
1. Start the server: `go run cmd/server/main.go`
2. Open browser to `http://localhost:8080`
3. Use the interactive buttons to test different endpoints
4. Monitor the console for real-time feedback

### Using the Command Line Client
1. Start the server: `go run cmd/server/main.go`
2. In another terminal: `go run cmd/client/main.go`
3. Watch the client demonstrate various Go concepts

### Using curl
```bash
# Health check
curl http://localhost:8080/health

# Get users
curl http://localhost:8080/api/users

# Create user
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "first_name": "Test",
    "last_name": "User",
    "age": 25,
    "active": true,
    "roles": ["user"]
  }'

# Calculate
curl -X POST http://localhost:8080/api/calculate \
  -H "Content-Type: application/json" \
  -d '{
    "operation": "add",
    "a": 10.5,
    "b": 20.3,
    "precision": 2
  }'
```

## 📖 Go Concepts Covered

### Core Language Features
- **Structs and Methods**: Data modeling and behavior attachment
- **Interfaces**: Abstraction and polymorphism
- **Goroutines**: Lightweight concurrency
- **Channels**: Communication between goroutines
- **Error Handling**: Explicit error propagation
- **Context**: Request lifecycle management

### HTTP and Web Development
- **HTTP Server**: Creating REST APIs with `net/http`
- **HTTP Client**: Making HTTP requests with retry logic
- **Middleware**: Request/response processing pipeline
- **JSON Handling**: Request/response serialization
- **CORS**: Cross-origin resource sharing
- **Rate Limiting**: Request throttling

### Software Engineering Practices
- **Dependency Injection**: Service interfaces and composition
- **Configuration Management**: Environment-based settings
- **Logging**: Structured logging with request tracking
- **Error Handling**: Graceful error propagation
- **Graceful Shutdown**: Clean application termination
- **Package Organization**: Professional project structure

### Concurrency Patterns
- **Worker Pools**: Managing concurrent tasks
- **Pipeline Pattern**: Sequential processing stages
- **Fan-out/Fan-in**: Distributing and collecting work
- **Request Parallelization**: Concurrent HTTP requests
- **Mutex Usage**: Thread-safe data access

## 🎯 Learning Exercises

### Beginner Exercises
1. **Modify the User Model**: Add a new field to the User struct and update the validation
2. **Add a New Endpoint**: Create a new API endpoint for user statistics
3. **Implement Authentication**: Add JWT token-based authentication
4. **Add Database Support**: Replace in-memory storage with a real database

### Intermediate Exercises
1. **Implement WebSockets**: Replace the simulation with real WebSocket connections
2. **Add Rate Limiting**: Implement IP-based rate limiting with Redis
3. **Create Unit Tests**: Write comprehensive unit tests for services
4. **Add Metrics**: Implement Prometheus metrics collection

### Advanced Exercises
1. **Microservices Architecture**: Split into multiple services
2. **gRPC Implementation**: Add gRPC alongside HTTP
3. **Event-Driven Architecture**: Implement event sourcing
4. **Container Orchestration**: Deploy with Kubernetes

## 🔍 Code Exploration Tips

1. **Start with main.go files**: Begin with `cmd/server/main.go` to understand the entry point
2. **Follow the request flow**: Trace how HTTP requests are processed through middleware → handlers → services
3. **Study the interfaces**: Understand how interfaces enable dependency injection and testing
4. **Examine error handling**: Notice how errors are propagated and handled at each layer
5. **Analyze concurrency**: Look at goroutine usage in services and the client
6. **Review configuration**: See how configuration is loaded and validated

## 🤝 Contributing

This is an educational project designed to teach Go concepts. Feel free to:
- Add new endpoints demonstrating additional Go features
- Improve existing code with better patterns
- Add more comprehensive examples
- Create additional learning exercises
- Enhance documentation and comments

## 📚 Additional Resources

### Go Documentation
- [Official Go Documentation](https://golang.org/doc/)
- [Effective Go](https://golang.org/doc/effective_go.html)
- [Go by Example](https://gobyexample.com/)
- [Go Web Examples](https://gowebexamples.com/)

### HTTP and Web Development
- [Go net/http Package](https://golang.org/pkg/net/http/)
- [HTTP Middleware Patterns](https://www.alexedwards.net/blog/making-and-using-middleware)
- [RESTful API Design](https://restfulapi.net/)

### Concurrency
- [Go Concurrency Patterns](https://golang.org/doc/effective_go.html#concurrency)
- [Advanced Go Concurrency](https://www.oreilly.com/library/view/concurrency-in-go/9781491941294/)

## 📝 License

This project is created for educational purposes. Feel free to use, modify, and distribute for learning Go programming.

---

**Happy Learning!** 🎉

This project demonstrates professional Go development practices while maintaining educational clarity. Every concept is explained through practical implementation, making it an excellent resource for learning Go from beginner to advanced levels.
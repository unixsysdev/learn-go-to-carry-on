
# Go Learning Exercises: Intermediate Level

## Table of Contents
1. [Introduction](#introduction)
2. [Intermediate Exercises](#intermediate-exercises)
   - [Exercise 5: Implement WebSockets](#exercise-5-implement-websockets)
   - [Exercise 6: Add Rate Limiting](#exercise-6-add-rate-limiting)
   - [Exercise 7: Create Unit Tests](#exercise-7-create-unit-tests)
   - [Exercise 8: Add Metrics](#exercise-8-add-metrics)

## Introduction

This document provides a series of intermediate-level exercises designed to help you learn Go programming by extending the existing application. These exercises introduce more complex concepts and external dependencies.

Each exercise includes:
- A clear objective
- Step-by-step instructions
- Code examples
- Testing guidance
- Explanations of key concepts

We assume you have basic knowledge of Go from the beginner exercises. Each exercise builds on the previous ones, so it's recommended to complete them in order.

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

WebSockets are a protocol that allows full-duplex (two-way) communication between client and server over a single TCP connection. Unlike HTTP which is request-response, WebSockets stay open for continuous messaging, perfect for chat, notifications, live updates.

In Go, we use the gorilla/websocket library for this, as standard library has limited WebSocket support.

#### Step 1: Install Required Packages

First, we need to install a WebSocket library for Go. We'll use the popular `github.com/gorilla/websocket` package.

1. Open your terminal in the project root and run:

```bash
go get github.com/gorilla/websocket
```

This adds the dependency to go.mod. The library provides tools to upgrade HTTP to WebSocket and handle messages.

**Explanation for Beginners:**
- External libraries extend Go's standard library. Gorilla WebSocket is widely used for WebSocket in Go.
- After getting, run `go mod tidy` to ensure modules are clean.

#### Step 2: Update the WebSocket Service

1. Open [`internal/services/services.go`](internal/services/services.go)
2. Replace the WebSocketService implementation with a real one. The service manages connections, broadcasting, etc.

Replace the existing WebSocketService (likely a simple struct) with this full implementation:

```go
/*
WEBSOCKET SERVICE IMPLEMENTATION
Implements real WebSocket functionality
*/

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "sync"
    "time"

    "github.com/gorilla/websocket"
)

type WebSocketService struct {
    connections map[string]*websocket.Conn // User ID to WebSocket connection mapping
    mu          sync.RWMutex              // Mutex for connection access
    upgrader    websocket.Upgrader        // WebSocket upgrader
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
                // In production, you should implement proper origin checking to prevent CSRF attacks
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
    
    // Close the connection gracefully
    if err := conn.Close(); err != nil {
        log.Printf("Error closing WebSocket connection for user %s: %v", userID, err)
    }
    
    // Remove the connection from the map
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
    
    // Marshal the message to JSON bytes
    messageJSON, err := json.Marshal(message)
    if err != nil {
        return fmt.Errorf("failed to marshal message: %w", err)
    }
    
    // Send message to all users concurrently using goroutines
    var wg sync.WaitGroup
    errors := make(chan error, len(s.connections))
    
    for userID, conn := range s.connections {
        wg.Add(1)
        go func(id string, c *websocket.Conn) {
            defer wg.Done()
            
            // Set write deadline to prevent hanging forever
            if err := c.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
                errors <- fmt.Errorf("failed to set write deadline for user %s: %w", id, err)
                return
            }
            
            // Write the message as text message
            if err := c.WriteMessage(websocket.TextMessage, messageJSON); err != nil {
                errors <- fmt.Errorf("failed to write message to user %s: %w", id, err)
            }
        }(userID, conn)
    }
    
    // Wait for all goroutines to finish
    wg.Wait()
    close(errors)
    
    // Collect any errors
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

// HandleConnection handles a WebSocket connection for a specific user
func (s *WebSocketService) HandleConnection(w http.ResponseWriter, r *http.Request, userID string) {
    // Upgrade the HTTP connection to WebSocket
    conn, err := s.upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Printf("Failed to upgrade connection for user %s: %v", userID, err)
        return
    }
    defer conn.Close()
    
    // Register the user connection
    if err := s.RegisterUser(userID, conn); err != nil {
        log.Printf("Failed to register user %s: %v", userID, err)
        return
    }
    defer s.UnregisterUser(userID)
    
    log.Printf("WebSocket connection established for user %s", userID)
    
    // Send welcome message to the user
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
    
    // Main loop for handling incoming messages
    for {
        // Set read deadline to detect inactive connections
        if err := conn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
            log.Printf("Failed to set read deadline for user %s: %v", userID, err)
            break
        }
        
        // Read message from the connection
        messageType, messageData, err := conn.ReadMessage()
        if err != nil {
            if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
                log.Printf("WebSocket connection closed unexpectedly for user %s: %v", userID, err)
            }
            break
        }
        
        // Handle text messages (JSON)
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

**Explanation for Beginners:**
- The service uses a map to store connections by user ID for quick lookup.
- `sync.RWMutex` for concurrent access – RLock for reading, Lock for writing to prevent race conditions in multi-threaded environment.
- Upgrader upgrades HTTP to WebSocket; CheckOrigin allows connections (in production, restrict to your domain to prevent cross-site WebSocket hijacking).
- Register/Unregister manage the map with locks for safety.
- BroadcastMessage uses goroutines to send to all, with WaitGroup to wait for all sends to complete.
- HandleConnection is called from the handler; it upgrades, registers, loops to read messages, broadcasts, and cleans up with defer.
- json.Marshal/Unmarshal for JSON handling – import "encoding/json".
- Deadlines prevent hanging; websocket.TextMessage is the message type for text data.
- The loop runs until close or error, handling one message at a time per connection.

Don't forget to add the necessary imports at the top of services.go if not already present: "encoding/json", "fmt", "log", "net/http", "sync", "time", "github.com/gorilla/websocket".

#### Step 3: Update the WebSocket Handler

1. Open [`internal/handlers/handlers.go`](internal/handlers/handlers.go)
2. The WebSocketHandler is likely a struct with wsService. Update the HandleWebSocket method to extract userID from query and call the service.

Replace the HandleWebSocket method with this:

```go
/*
WEBSOCKET HANDLER
Handles real WebSocket connections
*/

// HandleWebSocket handles WebSocket upgrade and message exchange
func (h *WebSocketHandler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
    // Extract user ID from query parameters (e.g., /ws?user_id=alice)
    userID := r.URL.Query().Get("user_id")
    if userID == "" {
        sendErrorResponse(w, "User ID is required", "MISSING_USER_ID", 
            http.StatusBadRequest, getRequestID(r))
        return
    }
    
    // Delegate to the service for handling the actual connection
    h.wsService.HandleConnection(w, r, userID)
}
```

**Explanation for Beginners:**
- r.URL.Query().Get("user_id") gets the "user_id" parameter from the URL query string.
- If missing, send 400 error using the helper function.
- The service handles the upgrade and message loop – the handler just extracts the param and calls the service method.
- This separates concerns: handler for HTTP routing, service for WebSocket logic.

#### Step 4: Create a Simple WebSocket Client

For testing purposes, let's create a simple HTML client that can connect to our WebSocket server. This will allow you to see real-time messaging in action.

1. Create a new file [`web/websocket.html`](web/websocket.html) with the following content. The web folder is for static files served by the server.

The full HTML file:

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
        // Get user ID from URL parameters (e.g., websocket.html?user_id=user1)
        const urlParams = new URLSearchParams(window.location.search);
        const userId = urlParams.get('user_id') || 'anonymous';
        
        // Connect to WebSocket server
        const ws = new WebSocket(`ws://localhost:8080/ws?user_id=${userId}`);
        
        // Handle incoming messages from server
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
        
        // Display message in the UI
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
            messagesDiv.scrollTop = messagesDiv.scrollHeight; // Scroll to bottom
        }
        
        // Handle Enter key in input field to send message
        document.getElementById('messageInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
    </script>
</body>
</html>
```

**Explanation for Beginners:**
- This is a simple HTML page with JavaScript for the WebSocket client.
- The URL param ?user_id=user1 is passed to /ws?user_id=user1 for identification.
- new WebSocket(url) creates the client connection to ws:// (WebSocket protocol, not http).
- onmessage handles incoming JSON from server, parses and displays.
- sendMessage() creates JSON object and sends via ws.send().
- Styles make system messages gray, user messages blue.
- Enter key triggers send.

#### Step 5: Test Your Implementation

1. Run the application:

```bash
go run cmd/server/main.go
```

2. Open two browser tabs and navigate to the client with different user_ids:

```
http://localhost:8080/websocket.html?user_id=user1
http://localhost:8080/websocket.html?user_id=user2
```

3. Type a message in one tab and press Send or Enter. You should see the welcome message first, then the chat message appear in both tabs in real-time.

If connections fail, check server logs for errors like upgrade failed (check CORS middleware allows ws).

#### Key Concepts Explained

1. **WebSocket Protocol**: WebSocket is a communication protocol that provides full-duplex communication channels over a single TCP connection. It's designed for real-time web applications like chat apps, live notifications, or collaborative editing. The protocol starts with an HTTP upgrade request.

2. **Connection Upgrade**: The HTTP connection is "upgraded" to a WebSocket connection using the `Upgrade` header in the HTTP response. This is handled by the `websocket.Upgrader`. The client sends an Upgrade header, server responds with 101 Switching Protocols if accepted.

3. **Message Handling**: The server reads messages from the WebSocket connection using ReadMessage(), processes them (here, just broadcasts to all), and can broadcast to other connected clients. Messages are binary or text; we use text for JSON payloads.

4. **Concurrency**: WebSocket connections are handled concurrently using goroutines (Go's lightweight threads). Each connection's loop runs in its own goroutine, allowing the server to handle many connections simultaneously without blocking the main server.

5. **Connection Lifecycle**: The server manages the lifecycle of WebSocket connections, including registration in a map, message handling loop, and cleanup when connections are closed or errors occur. defer statements ensure resources are released.

#### Troubleshooting

- **Connection Error**: If you get an error connecting to the WebSocket, make sure the server is running and that you're using the correct URL (ws://localhost:8080/ws?user_id=user1). Check the browser console for JavaScript errors.

- **CORS Error**: If you get a CORS error, make sure your CORS middleware is configured correctly to allow WebSocket connections. The upgrader's CheckOrigin should return true for your domain.

- **Message Not Received**: If messages aren't being received, check that the JSON marshaling/unmarshaling is working correctly (use console.log in JS to debug) and that there are no errors in the server logs (go run prints them to stdout).

- **Connection Timeout**: If connections are timing out, check that the read/write deadlines are set appropriately (60s for read, 5s for write) and that there are no network issues. Increase timeouts for testing.

- **Goroutine Leaks**: If you have many connections, monitor with `go tool pprof` for goroutine leaks, but for this exercise with few connections, it's fine.

Continue to Exercise 6 once this works.

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

Redis is an in-memory data structure store, used as a database, cache, and message broker. It's perfect for rate limiting because it's fast and supports atomic operations like incrementing counters.

Cross-cutting concerns like rate limiting, logging, and authentication are handled by middleware – functions that wrap the main handler to add behavior without modifying the core logic.

#### Step 1: Install Required Packages

First, we need to install a Redis client for Go.

1. Open your terminal in the project root and run:

```bash
go get github.com/go-redis/redis/v8
```

This adds the Redis client library to your go.mod file.

**Explanation for Beginners:**
- The go-redis library provides a client to connect to Redis and perform operations like setting keys, incrementing values, and setting expiration times.
- v8 is the current version at the time of writing; check for updates with `go list -m all | grep redis`.

#### Step 2: Update the Configuration

1. Open [`internal/config/config.go`](internal/config/config.go)
2. Add rate limiting configuration fields to the Config struct. These will be loaded from environment variables or defaults.

Add these fields inside the Config struct:

```go
type Config struct {
    // ... existing fields ...
    
    // Rate limiting configuration
    EnableRateLimit bool   `json:"enable_rate_limit"` // Enable rate limiting
    RateLimitRPS    int    `json:"rate_limit_rps"`    // Requests per second per IP
    RateLimitBurst  int    `json:"rate_limit_burst"`  // Burst size for rate limiting (allows short bursts)
    RedisHost       string `json:"redis_host"`        // Redis host
    RedisPort       string `json:"redis_port"`        // Redis port
    RedisPassword   string `json:"redis_password"`    // Redis password
    RedisDB         int    `json:"redis_db"`          // Redis database number
}
```

3. Update the `LoadConfig` function to include rate limiting configuration. Find the place where the config is initialized and add these lines:

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

**Explanation for Beginners:**
- `getEnvBoolOrDefault`, `getEnvIntOrDefault`, `getEnvOrDefault` are helper functions (assume they exist or add them if needed) that read environment variables and return defaults if not set.
- RPS (requests per second) limits to 10 requests per second per IP.
- Burst allows up to 20 requests in a burst.
- Environment variables are a way to configure the application without hardcoding values, especially for sensitive data like passwords.

You can set these environment variables in your terminal before running the application:

```bash
export ENABLE_RATE_LIMIT=true
export RATE_LIMIT_RPS=10
export RATE_LIMIT_BURST=20
export REDIS_HOST=localhost
export REDIS_PORT=6379
export REDIS_PASSWORD=
export REDIS_DB=0
```

#### Step 3: Create a Rate Limiting Service

1. Create a new file [`internal/services/ratelimiter.go`](internal/services/ratelimiter.go) with the following content. This service will handle the logic for checking and updating rate limits using Redis.

The complete file:

```go
package services

import (
    "context"
    "fmt"
    "strconv"
    "time"

    "github.com/go-redis/redis/v8"
)

// RateLimiterService handles rate limiting logic using a simple fixed window algorithm
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

// IsAllowed checks if a request from the given IP is allowed under the rate limit
func (s *RateLimiterService) IsAllowed(ip string, limit int, window time.Duration) (bool, error) {
    ctx := context.Background()
    
    // Create a unique key for the IP in Redis
    key := fmt.Sprintf("rate_limit:%s", ip)
    
    // Get the current count for this IP
    count, err := s.redisClient.Get(ctx, key).Int()
    if err == redis.Nil {
        // If the key doesn't exist, this is the first request - set it to 1 with expiration
        err := s.redisClient.Set(ctx, key, 1, window).Err()
        if err != nil {
            return false, fmt.Errorf("failed to set rate limit key: %w", err)
        }
        return true, nil
    } else if err != nil {
        return false, fmt.Errorf("failed to get rate limit count: %w", err)
    }
    
    // Check if the current count exceeds the limit
    if count >= limit {
        return false, nil // Rate limited
    }
    
    // Increment the count atomically
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

// SlidingWindowRateLimiter implements a more sophisticated rate limiting algorithm using sliding window
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
    
    // Current timestamp in seconds
    now := time.Now().Unix()
    
    // Remove old entries outside the window using ZRemRangeByScore (sorted set)
    minTimestamp := now - int64(window.Seconds())
    _, err := s.redisClient.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(minTimestamp, 10)).Result()
    if err != nil {
        return false, fmt.Errorf("failed to remove old entries: %w", err)
    }
    
    // Add current request timestamp to the sorted set
    _, err = s.redisClient.ZAdd(ctx, key, &redis.Z{
        Score:  float64(now),
        Member: strconv.FormatInt(now, 10),
    }).Result()
    if err != nil {
        return false, fmt.Errorf("failed to add request to window: %w", err)
    }
    
    // Set expiration on the key to clean up after the window
    err = s.redisClient.Expire(ctx, key, window).Err()
    if err != nil {
        return false, fmt.Errorf("failed to set key expiration: %w", err)
    }
    
    // Count requests in the current window
    count, err := s.redisClient.ZCount(ctx, key, strconv.FormatInt(minTimestamp, 10), strconv.FormatInt(now, 10)).Result()
    if err != nil {
        return false, fmt.Errorf("failed to count requests in sliding window: %w", err)
    }
    
    // Allow if count is <= limit
    return count <= int64(limit), nil
}

// Close closes the Redis connection
func (s *SlidingWindowRateLimiter) Close() error {
    return s.redisClient.Close()
}
```

**Explanation for Beginners:**
- The RateLimiterService uses a simple fixed-window algorithm: it stores a counter in Redis for each IP, increments it for each request, and resets it after the window (e.g., 1 second).
- If the counter exceeds the limit, the request is blocked.
- The SlidingWindowRateLimiter uses a Redis sorted set (ZSET) to store timestamps of requests. It removes old timestamps outside the window and counts how many are within the current window.
- `context.Background()` creates a context for Redis operations (required for cancellation, but here basic).
- `strconv.FormatInt(now, 10)` converts the Unix timestamp to string for Redis.
- Atomic operations like Incr ensure thread-safety in Redis.
- This allows more granular limiting than fixed window, avoiding bursts at window boundaries.

#### Step 4: Update the Rate Limiting Middleware

1. Open [`internal/middleware/middleware.go`](internal/middleware/middleware.go)
2. Add the Redis-based rate limiting middleware at the end of the file. This middleware will wrap the application's router to check the rate limit before allowing requests to reach the handlers.

Add this code:

```go
/*
REDIS-BASED RATE LIMITING MIDDLEWARE
Implements IP-based rate limiting with Redis
*/

// RedisRateLimitMiddleware creates a Redis-based rate limiting middleware
func RedisRateLimitMiddleware(rateLimiter services.RateLimiterServiceInterface, limit int, window time.Duration) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Get the client's IP address
            clientIP := getClientIP(r)
            
            // Check if the request is allowed under the rate limit
            allowed, err := rateLimiter.IsAllowed(clientIP, limit, window)
            if err != nil {
                log.Printf("[RateLimit] Error checking rate limit for IP %s: %v", clientIP, err)
                // In case of error (e.g., Redis down), continue processing to avoid DoS from Redis failure
                next.ServeHTTP(w, r)
                return
            }
            
            if !allowed {
                requestID := getRequestIDFromContext(r)
                log.Printf("[RateLimit] Rate limit exceeded for IP %s (Request ID: %s)", clientIP, requestID)
                
                // Send HTTP 429 Too Many Requests response
                w.Header().Set("Content-Type", "application/json")
                w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
                w.Header().Set("X-RateLimit-Remaining", "0")
                w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(window).Unix()))
                w.WriteHeader(http.StatusTooManyRequests)
                
                // Send JSON error response
                fmt.Fprintf(w, `{"error": "Rate limit exceeded", "code": "RATE_LIMIT_EXCEEDED", "message": "Too many requests. Please try again later."}`)
                return
            }
            
            // Add rate limit headers to successful responses for client information
            w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
            w.Header().Set("X-RateLimit-Remaining", "1") // Simplified; in real implementation, track remaining requests
            
            // If allowed, call the next handler in the chain
            next.ServeHTTP(w, r)
        })
    }
}

// getClientIP extracts the client IP from the request (implement if not already present)
func getClientIP(r *http.Request) string {
    // Check for forwarded IP (behind proxies/load balancers)
    ip := r.Header.Get("X-Forwarded-For")
    if ip == "" || ip == "unknown" {
        ip = r.Header.Get("X-Real-IP")
    }
    if ip == "" || ip == "unknown" {
        ip = r.RemoteAddr
    }
    return ip
}

// getRequestIDFromContext gets the request ID from the request context (implement if not already present)
func getRequestIDFromContext(r *http.Request) string {
    // Assume a request ID is stored in context by earlier middleware
    return r.Context().Value("request_id").(string)
}
```

**Explanation for Beginners:**
- The middleware is a function that returns another function wrapping the next handler in the chain.
- `getClientIP(r)` gets the real client IP, handling proxies (X-Forwarded-For header is common in production).
- If not allowed, it sends an HTTP 429 status with informative headers (standard for rate limiting).
- Headers like X-RateLimit-Limit tell clients the max rate, Remaining shows how many left (simplified here).
- If allowed, it adds headers and calls next.ServeHTTP(w, r).
- fmt.Fprintf writes formatted JSON error.

You may need to add imports for "fmt", "log", "net/http", "time" if not present.

#### Step 5: Update the Main Function

1. Open [`cmd/server/main.go`](cmd/server/main.go)
2. Add the necessary import for context if not already present:

```go
import (
    // ... existing imports ...
    "context" // Add this if not present
)
```

3. After initializing other services (userService, authService, etc.), initialize the rate limiter:

```go
// ... after authService initialization ...

// Initialize rate limiter if enabled
var rateLimiter services.RateLimiterServiceInterface
if config.EnableRateLimit {
    rateLimiter = services.NewRateLimiterService(
        config.RedisHost,
        config.RedisPort,
        config.RedisPassword,
        config.RedisDB,
    )
    defer rateLimiter.Close()
    
    // Test the Redis connection
    ctx := context.Background()
    if err := rateLimiter.(*services.RateLimiterService).redisClient.Ping(ctx).Err(); err != nil {
        log.Printf("Warning: Failed to connect to Redis, rate limiting will be disabled: %v", err)
        rateLimiter = nil
    }
}
```

4. Update the middleware chain to include the rate limiting middleware. Find the place where the middleware is applied to the mux (router) and wrap it with the rate limiter. For example:

```go
// Apply middleware chain
handler := middleware.LoggingMiddleware(
    middleware.RecoveryMiddleware(
        middleware.CORSMiddleware(
            middleware.RequestIDMiddleware(
                middleware.AuthMiddleware(authService)(
                    // Wrap the mux with rate limiting middleware
                    middleware.RedisRateLimitMiddleware(rateLimiter, config.RateLimitRPS, time.Second)(mux),
                ),
            ),
        ),
    ),
)
```

**Explanation for Beginners:**
- We create the rate limiter only if enabled.
- `defer rateLimiter.Close()` ensures the connection is closed when the application shuts down.
- Ping tests if Redis is reachable; if not, disable to avoid blocking all requests.
- The middleware chain is applied from inner to outer: rate limit first (before auth), then auth, then the mux.
- `time.Second` is the window for 1-second intervals; adjust based on config.RateLimitRPS.

#### Step 6: Set Up Redis

Before running the application, you need to set up a Redis server. Redis is a fast in-memory database that we'll use to store rate limiting counters.

1. Install Redis if you haven't already:

   - On Ubuntu/Debian: `sudo apt-get install redis-server`
   - On macOS (using Homebrew): `brew install redis`
   - On Windows: Download the Redis installer from the official Redis website (redis.io/download) and run redis-server.exe

2. Start the Redis server:

   - On Ubuntu/Debian: `sudo service redis-server start` or `redis-server` to run manually
   - On macOS: `brew services start redis`
   - On Windows: Run `redis-server.exe` from the installation directory

3. Verify Redis is running by opening another terminal and running:

```bash
redis-cli ping
```

You should see `PONG` as the response. If not, check the installation and start the service.

4. Optionally, set environment variables for the Redis connection if using non-default settings:

```bash
export REDIS_HOST=localhost
export REDIS_PORT=6379
export REDIS_PASSWORD=  # Leave empty for no password
export REDIS_DB=0
```

**Explanation for Beginners:**
- Redis runs as a service/daemon. It's lightweight and starts quickly.
- The default configuration uses database 0 (Redis supports 16 databases).
- In production, secure Redis with a password and bind to localhost.

#### Step 7: Test Your Implementation

1. Run the application:

```bash
go run cmd/server/main.go
```

The server should start without errors, and you should see a log message if Redis connection fails.

2. Test rate limiting by sending a series of requests rapidly. You can use a simple bash loop or a tool like Apache Bench (ab). Here's a bash example to simulate 15 requests with a 0.1-second delay between them (should allow 10, block 5):

```bash
# Simple bash script to test rate limiting
for i in {1..15}; do
    echo "Sending request $i"
    response=$(curl -s -w "HTTPSTATUS: %{http_code}\n" -o /dev/null -X GET "http://localhost:8080/health")
    http_status=$(echo $response | cut -d ' ' -f2)
    echo "Request $i status: $http_status"
    if [ $http_status == "429" ]; then
        echo "Rate limit hit!"
    fi
    sleep 0.1  # Small delay to simulate rapid requests
done
```

You should see the first 10 requests return HTTP 200 OK, and the next 5 return 429 Too Many Requests with the error message in JSON.

3. Test with curl to see headers on successful requests:

```bash
curl -I -X GET http://localhost:8080/health
```

Look for X-RateLimit-Limit and X-RateLimit-Remaining headers.

**Explanation for Beginners:**
- The loop sends GET /health (a simple endpoint) 15 times quickly.
- The first 10 should pass, the rest blocked.
- Use `-I` for head only to see headers.
- In a real test, use a tool like `ab -n 15 -c 1 http://localhost:8080/health` for concurrent.

#### Key Concepts Explained

1. **Rate Limiting**: Rate limiting is a technique to control the rate of traffic sent or received by a server. It's used to prevent abuse (like DDoS attacks), manage resource usage, and ensure fair access to your API. Without it, a single client could overwhelm your server.

2. **Redis**: Redis is an in-memory data structure store, used as a database, cache, and message broker. We use it to store rate limiting counters because it's extremely fast for simple operations like incrementing numbers and setting expiration times. Redis keys are strings, and we use them to track per-IP counters.

3. **Fixed Window vs. Sliding Window**: The simple rate limiter uses a fixed window algorithm, which counts requests in fixed time windows (e.g., from 00:00 to 00:01). This can allow bursts at window edges. The sliding window algorithm provides more accurate rate limiting by tracking individual request timestamps in a sliding time window using Redis sorted sets, avoiding those edge bursts.

4. **Distributed Rate Limiting**: By using Redis as the storage backend, we can implement distributed rate limiting that works across multiple instances of our application (important for scalability with load balancers or microservices). Each server instance shares the same Redis, so the count is global.

5. **Headers**: We include standard rate limiting headers in the response (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset) to inform clients about their current rate limit status. This is a best practice for API design, allowing clients to implement exponential backoff for retries.

#### Troubleshooting

- **Redis Connection Error**: If you get an error connecting to Redis (e.g., "dial tcp 127.0.0.1:6379: connect: connection refused"), make sure Redis is installed and running. Use `redis-cli ping` to test – it should return "PONG". Start with `redis-server` if needed.

- **Rate Limiting Not Working**: If rate limiting doesn't seem to be working, check that the `ENABLE_RATE_LIMIT` environment variable is set to `true` (echo $ENABLE_RATE_LIMIT) and that there are no errors in the server logs when requests are made. Also, ensure the middleware is applied in the chain.

- **All Requests Blocked**: If all requests are being blocked (all 429), check that your rate limit settings are reasonable (e.g., RATE_LIMIT_RPS=10 is not too low) and that Redis is storing and retrieving counters correctly. Use `redis-cli keys "*rate_limit*"` to see if keys are being created for your IP.

- **Middleware Order**: Ensure the rate limiting middleware is applied early in the chain (before auth) if you want to limit all requests, including login. If placed after, it might not limit public endpoints.

- **No Redis Keys**: If no keys are created in Redis, check the clientIP function – it might be getting the wrong IP (e.g., 127.0.0.1 vs your actual IP). Test with curl from different terminals/IPs.

Continue to Exercise 7 once this works.

### Exercise 7: Create Unit Tests

#### Objective

Write comprehensive unit tests for the services to ensure they work correctly and to prevent regressions.

#### What You'll Learn

- How to write unit tests in Go
- How to use the testing package
- How to create test doubles (mocks and stubs)
- How to use test assertions

#### Background

Unit tests are automated tests that verify the correctness of individual units of code (such as functions or methods) in isolation. They're essential for maintaining code quality and preventing regressions when you make changes to the codebase.

In Go, the built-in `testing` package is used for unit testing. Tests are written in files ending with `_test.go` and are run with the `go test` command. Tests help ensure that your code behaves as expected and catches bugs early.

Test doubles like mocks allow you to test a component without depending on real dependencies (e.g., a real database). This makes tests faster and more reliable.

#### Step 1: Create Test Files

In Go, test files are created by adding `_test.go` to the name of the file being tested. For example, tests for `services.go` would be in `services_test.go`. The `go test` command automatically discovers and runs these tests.

1. Create a test file for the services from the project root:

```bash
touch internal/services/services_test.go
```

2. Create a test file for the models:

```bash
touch internal/models/models_test.go
```

**Explanation for Beginners:**
- Tests are kept separate from production code to keep the codebase clean and focused.
- Run all tests with `go test ./...` from the project root, or `go test` inside the package directory.
- The testing framework runs each test function (starting with Test) and reports failures with line numbers.

#### Step 2: Write Tests for the User Model

1. Open [`internal/models/models_test.go`](internal/models/models_test.go) and add the following content. This tests the validation methods and other methods on the User struct that we added in previous exercises.

The complete content for the models test file:

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

    // Run each test case
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

    // Run each test case
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

    // Run each test case
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

    // Run each test case
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

    // Run each test case
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            user := &User{
                Age: tt.age,
            }
            
            actual := user.IsAdult()
            if actual != tt.expected {
                t.Errorf("User.IsAdult
# Go Learning Exercises: Advanced Level

## Table of Contents
1. [Introduction](#introduction)
2. [Advanced Exercises](#advanced-exercises)
   - [Exercise 9: Microservices Architecture](#exercise-9-microservices-architecture)
   - [Exercise 10: gRPC Implementation](#exercise-10-grpc-implementation)
   - [Exercise 11: Event-Driven Architecture](#exercise-11-event-driven-architecture)
   - [Exercise 12: Container Orchestration](#exercise-12-container-orchestration)

## Introduction

This document provides a series of advanced-level exercises designed to help you learn Go programming by extending the existing application. These exercises explore architectural patterns and deployment strategies for production-ready systems.

Each exercise includes:
- A clear objective
- Step-by-step instructions
- Code examples
- Testing guidance
- Explanations of key concepts

We assume you have intermediate knowledge of Go from the previous exercises. Each exercise builds on the previous ones, so it's recommended to complete them in order. These exercises introduce concepts like microservices, gRPC, event-driven architecture, and container orchestration, which are essential for scalable, distributed systems.

## Advanced Exercises

### Exercise 9: Microservices Architecture

#### Objective

Split the monolithic application into multiple microservices to improve scalability and maintainability.

#### What You'll Learn

- How to design and implement a microservices architecture in Go
- How to communicate between services using HTTP or gRPC
- How to manage service dependencies and configuration
- How to handle service discovery and load balancing

#### Background

Currently, the application is a monolith – all components (handlers, services, models) are in one binary. Microservices architecture breaks it into independent services, each responsible for a specific domain (e.g., user service, auth service). This allows independent scaling, technology choice, and development.

In Go, each microservice is a separate binary, communicating via HTTP/gRPC. We'll split into UserService (handles users), AuthService (handles authentication), and API Gateway (routes requests).

This exercise focuses on splitting the user and auth logic into separate services.

#### Step 1: Create the User Microservice

1. Create a new directory for the user service: `mkdir -p microservices/user-service && cd microservices/user-service`

2. Initialize a new Go module for the user service:

```bash
go mod init microservices/user-service
```

3. Copy the relevant files from the main project: models.go, services.go (user parts), and create main.go for the user service.

Create `microservices/user-service/main.go`:

```go
package main

import (
    "log"
    "net/http"

    "scholastic-go-tutorial/internal/config"
    "scholastic-go-tutorial/internal/models"
    "scholastic-go-tutorial/internal/services"
)

func main() {
    // Load configuration
    cfg, err := config.LoadConfig()
    if err != nil {
        log.Fatal("Failed to load config:", err)
    }

    // Initialize services
    dbService, err := services.NewDatabaseService(cfg)
    if err != nil {
        log.Fatal("Failed to initialize database:", err)
    }
    defer dbService.Close()

    userService := services.NewUserService(dbService.DB)

    // Define HTTP handlers for user service
    mux := http.NewServeMux()
    mux.HandleFunc("/users", userService.GetAllUsersHandler)
    mux.HandleFunc("/users/", userService.GetUserByIDHandler)
    mux.HandleFunc("/users", userService.CreateUserHandler)
    mux.HandleFunc("/users/", userService.UpdateUserHandler)
    mux.HandleFunc("/users/", userService.DeleteUserHandler)

    // Start server on different port, e.g., 8081
    log.Println("User service starting on :8081")
    log.Fatal(http.ListenAndServe(":8081", mux))
}
```

**Explanation for Beginners:**
- Each microservice has its own main.go and go.mod.
- The user service only handles user-related endpoints.
- It uses the same internal packages, but in production, shared code would be in a common library.
- Server on :8081 to avoid port conflict with main app.

4. Copy models and services to microservices/user-service/internal/.

5. Run the user service:

```bash
cd microservices/user-service
go run main.go
```

Test with curl http://localhost:8081/users

#### Step 2: Create the Auth Microservice

1. Create directory: `mkdir -p microservices/auth-service && cd microservices/auth-service`

2. Initialize module:

```bash
go mod init microservices/auth-service
```

3. Create main.go for auth service, similar to user, but for auth endpoints:

```go
package main

import (
    "log"
    "net/http"

    "scholastic-go-tutorial/internal/config"
    "scholastic-go-tutorial/internal/services"
)

func main() {
    cfg, err := config.LoadConfig()
    if err != nil {
        log.Fatal("Failed to load config:", err)
    }

    dbService, err := services.NewDatabaseService(cfg)
    if err != nil {
        log.Fatal("Failed to initialize database:", err)
    }
    defer dbService.Close()

    authService := services.NewAuthService(someUserService, cfg.JWTSecret, cfg.JWTExpiration)

    mux := http.NewServeMux()
    mux.HandleFunc("/login", authService.LoginHandler)
    mux.HandleFunc("/protected", authService.ProtectedHandler)

    log.Println("Auth service starting on :8082")
    log.Fatal(http.ListenAndServe(":8082", mux))
}
```

**Explanation for Beginners:**
- Auth service handles login, token validation.
- It needs access to user service for validation, so in real, use service discovery like Consul or HTTP calls to user service.
- For simplicity, assume shared DB.

#### Step 3: Create API Gateway

1. In main project, create gateway to route /api/users to user service, /api/auth to auth service.

In main.go, use http.ReverseProxy to forward requests.

Add to main.go:

```go
import (
    "net/http"
    "net/http/httputil"
    "net/url"
)

func main() {
    // ... existing ...

    // API Gateway
    mux := http.NewServeMux()
    mux.HandleFunc("/api/users", proxyToUserService)
    mux.HandleFunc("/api/auth", proxyToAuthService)

    // ... middleware ...

    log.Fatal(http.ListenAndServe(":8080", mux))
}

// proxyToUserService forwards requests to user service
func proxyToUserService(w http.ResponseWriter, r *http.Request) {
    target, _ := url.Parse("http://localhost:8081")
    proxy := httputil.NewSingleHostReverseProxy(target)
    proxy.ServeHTTP(w, r)
}

// proxyToAuthService forwards to auth service
func proxyToAuthService(w http.ResponseWriter, r *http.Request) {
    target, _ := url.Parse("http://localhost:8082")
    proxy := httputil.NewSingleHostReverseProxy(target)
    proxy.ServeHTTP(w, r)
}
```

**Explanation for Beginners:**
- Reverse proxy forwards requests to backend services.
- httputil.NewSingleHostReverseProxy creates a proxy to the target service.
- This way, clients call one gateway, which routes to microservices.

#### Step 4: Test the Microservices Architecture

1. Run user service on :8081, auth on :8082, main gateway on :8080.

2. Test /api/users via gateway:

```bash
curl http://localhost:8080/api/users
```

It should forward to user service.

3. Test login via gateway:

```bash
curl -X POST http://localhost:8080/api/auth/login -H "Content-Type: application/json" -d '{"username": "alice_dev", "password": "password"}'
```

#### Key Concepts Explained

1. **Microservices Architecture**: Microservices break the application into small, independent services that communicate over the network. Each service is responsible for a specific business capability (e.g., users, auth). This improves scalability (scale each service independently), fault isolation (one service down doesn't take all), and technology diversity.

2. **Service Communication**: Services communicate using HTTP or gRPC. Here, we use HTTP reverse proxy for simplicity. In production, use service mesh like Istio for advanced routing.

3. **Service Discovery**: In real microservices, services discover each other dynamically (e.g., using Consul, etcd). Here, hard-coded URLs for simplicity.

4. **Configuration Management**: Each service has its own config, but shared DB for data consistency. In advanced setups, use config servers like Spring Cloud Config.

#### Troubleshooting

- **Port Conflicts**: Ensure each service runs on different ports.

- **Dependency Errors**: Each service needs its own go.mod with dependencies.

- **Database Connection**: All services share the DB, so config must be consistent.

- **Proxy Errors**: If proxy fails, check if backend services are running.

Continue to Exercise 10.

### Exercise 10: gRPC Implementation

#### Objective

Add gRPC alongside HTTP to provide a high-performance RPC interface for services.

#### What You'll Learn

- How to implement gRPC in Go
- How to define protobuf messages and services
- How to generate Go code from protobuf
- How to integrate gRPC with existing HTTP services

#### Background

gRPC is a high-performance RPC framework developed by Google. It uses Protocol Buffers (protobuf) for serialization, which is faster and more efficient than JSON for machine-to-machine communication. It's used for microservices to replace or supplement HTTP.

We'll add a gRPC server to the user service for gRPC calls.

#### Step 1: Install Required Packages

1. In the user service directory, run:

```bash
go get google.golang.org/grpc
go get google.golang.org/protobuf
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
```

**Explanation for Beginners:**
- grpc is the gRPC library for Go.
- protobuf is for defining messages.
- protoc-gen-go generates Go code from .proto files.

#### Step 2: Define Protobuf for User Service

1. Create `microservices/user-service/proto/user.proto`:

```proto
syntax = "proto3";

package user;

option go_package = "proto/user";

message User {
    int32 id = 1;
    string username = 2;
    string email = 3;
    string first_name = 4;
    string last_name = 5;
    int32 age = 6;
    bool active = 7;
    int64 created_at = 8;
    repeated string roles = 9;
}

message CreateUserRequest {
    string username = 1;
    string email = 2;
    string first_name = 3;
    string last_name = 4;
    int32 age = 5;
}

message CreateUserResponse {
    User user = 1;
}

service UserService {
    rpc GetUser(GetUserRequest) returns (User);
    rpc GetAllUsers(GetAllUsersRequest) returns (GetAllUsersResponse);
    rpc CreateUser(CreateUserRequest) returns (CreateUserResponse);
}

message GetUserRequest {
    int32 id = 1;
}

message GetAllUsersRequest {}

message GetAllUsersResponse {
    repeated User users = 1;
}
```

**Explanation for Beginners:**
- Protobuf is a language-agnostic way to define messages and services.
- syntax = "proto3" is the current version.
- Messages are like structs, fields numbered for serialization.
- Service defines RPC methods.

2. Generate Go code:

```bash
protoc --go_out=. --go_opt=paths=source_relative proto/user.proto
```

This creates proto/user/user.pb.go.

#### Step 3: Implement gRPC Server in User Service

1. In user service, create `grpc_server.go`:

```go
package main

import (
    "context"
    "log"
    "net"

    "google.golang.org/grpc"

    pb "scholastic-go-tutorial/microservices/user-service/proto/user"
    "scholastic-go-tutorial/internal/models"
    "scholastic-go-tutorial/internal/services"
)

type server struct {
    pb.UnimplementedUserServiceServer
    userService *services.UserService
}

func (s *server) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.User, error) {
    user, err := s.userService.GetUserByID(int(req.Id))
    if err != nil {
        return nil, err
    }
    return &pb.User{
        Id:        int32(user.ID),
        Username:  user.Username,
        Email:     user.Email,
        FirstName: user.FirstName,
        LastName:  user.LastName,
        Age:       int32(user.Age),
        Active:    user.Active,
        CreatedAt: user.CreatedAt.Unix(),
        Roles:     user.Roles,
    }, nil
}

func (s *server) GetAllUsers(ctx context.Context, req *pb.GetAllUsersRequest) (*pb.GetAllUsersResponse, error) {
    users, err := s.userService.GetAllUsers()
    if err != nil {
        return nil, err
    }
    
    pbUsers := []*pb.User{}
    for _, u := range users {
        pbUsers = append(pbUsers, &pb.User{
            Id:        int32(u.ID),
            Username:  u.Username,
            // ... other fields
        })
    }
    
    return &pb.GetAllUsersResponse{Users: pbUsers}, nil
}

func (s *server) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
    user := &models.User{
        Username:  req.Username,
        Email:     req.Email,
        FirstName: req.FirstName,
        LastName:  req.LastName,
        Age:       int(req.Age),
    }
    
    err := s.userService.CreateUser(user)
    if err != nil {
        return nil, err
    }
    
    pbUser := &pb.User{
        Id:        int32(user.ID),
        Username:  user.Username,
        // ... other fields
    }
    
    return &pb.CreateUserResponse{User: pbUser}, nil
}

func main() {
    // ... existing HTTP setup ...
    
    // gRPC server
    lis, err := net.Listen("tcp", ":50051")
    if err != nil {
        log.Fatal("Failed to listen:", err)
    }
    
    s := grpc.NewServer()
    pb.RegisterUserServiceServer(s, &server{userService: userService})
    
    log.Println("gRPC server starting on :50051")
    if err := s.Serve(lis); err != nil {
        log.Fatal("Failed to serve:", err)
    }
}
```

**Explanation for Beginners:**
- server implements the proto service.
- Methods map to RPC calls, using context for cancellation.
- Convert between models.User and pb.User.
- grpc.NewServer() creates gRPC server, Register registers the service.
- Serve on port 50051 (standard for gRPC).

#### Step 4: Test gRPC

1. Install grpcurl for testing:

```bash
go install google.golang.org/grpc/cmd/grpcurl@latest
```

2. Test GetUser:

```bash
grpcurl -plaintext -d '{"id": 1}' localhost:50051 user.UserService/GetUser
```

#### Key Concepts Explained

1. **gRPC**: gRPC is a high-performance, open-source universal RPC framework. It uses HTTP/2 for transport and Protocol Buffers for serialization. It's faster than REST/JSON for internal communication because protobuf is binary and compact.

2. **Protocol Buffers**: Protobuf is a language-neutral, platform-neutral mechanism for serializing structured data. It's like JSON but binary, smaller, and faster. .proto files define the schema, protoc generates code.

3. **RPC Methods**: Each method in the service is an RPC call, taking request and returning response. Context allows cancellation and metadata.

4. **Integration**: Run gRPC alongside HTTP by listening on different ports or using same server with grpc/http.

#### Troubleshooting

- **Proto Compilation**: If protoc fails, ensure PATH includes protoc, and go_package is correct.

- **gRPC Errors**: Use grpcurl or grpcui for testing. Check logs for binding errors.

Continue to Exercise 11.

### Exercise 11: Event-Driven Architecture

#### Objective

Implement event-driven architecture with message queues for decoupled services.

#### What You'll Learn

- How to implement event sourcing with events
- How to use message queues like RabbitMQ or Kafka
- How to publish and subscribe to events in Go
- How to handle event processing asynchronously

#### Background

Event-driven architecture (EDA) is a pattern where services communicate by producing and consuming events (messages about changes, like "UserCreated"). This decouples services – they don't call each other directly, but publish events to a queue.

We'll use RabbitMQ for this exercise.

#### Step 1: Install RabbitMQ

1. Install RabbitMQ server (docker or direct install).

For Docker:

```bash
docker run -d -p 5672:5672 -p 15672:15672 --name rabbitmq rabbitmq:3-management
```

Access management at http://localhost:15672.

#### Step 2: Add Event Publishing in User Service

1. Install AMQP client for Go:

```bash
go get github.com/rabbitmq/amqp091-go
```

2. In user service, after creating user, publish event:

In services.go CreateUser:

```go
// After successful create
err = s.publishEvent("user.created", map[string]interface{}{
    "user_id": user.ID,
    "username": user.Username,
    // ... other data
})
```

Implement publishEvent using amqp.

#### Step 3: Create Event Consumer Service

1. Create event service to consume events.

Create `microservices/event-service/main.go`:

```go
package main

import (
    "log"

    "github.com/rabbitmq/amqp091-go"
)

func main() {
    conn, err := amqp.Dial("amqp://guest:guest@localhost:5672/")
    if err != nil {
        log.Fatal("Failed to connect to RabbitMQ:", err)
    }
    defer conn.Close()

    ch, err := conn.Channel()
    if err != nil {
        log.Fatal("Failed to open channel:", err)
    }
    defer ch.Close()

    q, err := ch.QueueDeclare(
        "user_events", // queue name
        false,         // durable
        false,         // delete when unused
        false,         // exclusive
        false,         // no-wait
        nil,           // arguments
    )
    if err != nil {
        log.Fatal("Failed to declare queue:", err)
    }

    msgs, err := ch.Consume(
        q.Name,
        "",    // consumer tag
        true,  // auto ack
        false, // exclusive
        false, // no local
        false, // no wait
        nil,   // arguments
    )
    if err != nil {
        log.Fatal("Failed to register consumer:", err)
    }

    forever := make(chan bool)
    go func() {
        for d := range msgs {
            log.Printf("Received event: %s", d.Body)
            // Process event
        }
    }()

    log.Printf("Event service starting. Waiting for messages...")
    <-forever
}
```

**Explanation for Beginners:**
- amqp.Dial connects to RabbitMQ.
- QueueDeclare creates a queue for events.
- Consume gets messages from queue.
- In real, process event, e.g., send email on user created.

#### Step 4: Test Event-Driven

1. Run RabbitMQ, user service, event service.

2. Create user via HTTP, check event service logs for event.

#### Key Concepts Explained

1. **Event-Driven Architecture**: EDA uses events to decouple services. Producers publish events to queues, consumers subscribe. This makes systems resilient – if consumer down, events queue up.

2. **Message Queues**: RabbitMQ is a message broker. Events are messages in queues. AMQP is the protocol.

3. **Event Sourcing**: Store state as sequence of events. To get current state, replay events. Here, simple publish.

4. **Asynchronous Processing**: Events are processed async, allowing loose coupling.

#### Troubleshooting

- **RabbitMQ Not Running**: Check docker logs or service status.

- **Connection Errors**: Ensure host/port correct, guest/guest credentials.

- **No Events**: Check exchange/queue names match.

Continue to Exercise 12.

### Exercise 12: Container Orchestration

#### Objective

Deploy the microservices with Kubernetes for container orchestration.

#### What You'll Learn

- How to containerize Go applications with Docker
- How to use Kubernetes for deployment
- How to manage configuration and secrets in Kubernetes
- How to scale and monitor containerized services

#### Background

Container orchestration is managing multiple containers across machines. Kubernetes (K8s) is the leading tool, automating deployment, scaling, operations.

We'll dockerize the services and deploy to minikube (local K8s).

#### Step 1: Containerize Services with Docker

1. Create Dockerfile for user service in microservices/user-service/:

```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/main .
CMD ["./main"]
```

2. Build image:

```bash
docker build -t user-service:latest .
```

3. Do same for auth service.

#### Step 2: Set Up Minikube

1. Install minikube: https://minikube.sigs.k8s.io/docs/start/

2. Start minikube:

```bash
minikube start
```

#### Step 3: Deploy to Kubernetes

1. Create deployment yaml for user service: `user-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-service
spec:
  replicas: 1
  selector:
    matchLabels:
      app: user-service
  template:
    metadata:
      labels:
        app: user-service
    spec:
      containers:
      - name: user-service
        image: user-service:latest
        ports:
        - containerPort: 8081
```

2. Apply:

```bash
kubectl apply -f user-deployment.yaml
kubectl apply -f auth-deployment.yaml
kubectl apply -f gateway-deployment.yaml
```

3. Expose services with services.yaml.

#### Step 4: Test Deployment

1. Port-forward:

```bash
kubectl port-forward service/gateway 8080:8080
```

2. Test endpoints.

#### Key Concepts Explained

1. **Container Orchestration**: Kubernetes orchestrates containers, handling scaling, health checks, rolling updates.

2. **Docker**: Packages app and dependencies into container image for consistency across environments.

3. **Deployments**: K8s Deployment manages replicas of pods (running containers).

4. **Services**: K8s Service exposes pods, load balances.

#### Troubleshooting

- **Minikube Issues**: Check minikube status, logs with kubectl logs.

- **Image Pull Errors**: Ensure images built and tagged correctly.

- **Port Forward**: Use kubectl port-forward for local testing.

This completes the advanced exercises.
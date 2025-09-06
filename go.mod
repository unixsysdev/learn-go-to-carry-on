// go.mod - Go module definition file
// This file defines the module path and dependencies for our scholastic Go project
// Module name should be unique to your project and follow Go conventions
module scholastic-go-tutorial

// Go version requirement - specifies minimum Go version needed to compile this project
go 1.23

toolchain go1.24.7

// Dependencies will be automatically added here when we use 'go get' commands
// For now, we'll use only Go standard library which doesn't require explicit dependencies

require (
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.5.1 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
)

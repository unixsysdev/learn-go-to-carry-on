// internal/config/config.go - Configuration management package
// This package demonstrates Go's approach to configuration management
// It shows how to structure configuration, use environment variables,
// and implement configuration validation

package config

import (
	// Standard library imports
	"fmt"      // Formatted I/O for error messages
	"os"       // Operating system interface
	"strconv"  // String conversion utilities
	"strings"  // String manipulation functions
	"time"     // Time duration handling
)

/*
CONFIG STRUCTURE
Define configuration structure with JSON tags for potential future JSON config support
This struct holds all application configuration in a centralized location
Each field represents a configurable aspect of the application
*/
type Config struct {
	// Server configuration
	ServerPort    string        // Port number for HTTP server (e.g., "8080")
	ServerHost    string        // Host address to bind server (e.g., "localhost")
	ReadTimeout   time.Duration // Maximum duration for reading HTTP requests
	WriteTimeout  time.Duration // Maximum duration for writing HTTP responses
	IdleTimeout   time.Duration // Maximum idle time between requests

	// Application configuration
	AppName       string        // Application name for logging and identification
	DebugMode     bool          // Enable debug logging and features
	Environment   string        // Environment: development, staging, production

	// Database configuration (example for future expansion)
	DBHost        string        // Database host address
	DBPort        string        // Database port number
	DBName        string        // Database name
	DBUser        string        // Database username
	DBPassword    string        // Database password
	DBMaxConns    int           // Maximum database connections
	DBMaxIdle     int           // Maximum idle database connections

	// WebSocket configuration
	WSReadBufferSize  int       // WebSocket read buffer size in bytes
	WSWriteBufferSize int       // WebSocket write buffer size in bytes
	WSPingPeriod      time.Duration // WebSocket ping interval

	// Security configuration
	EnableHTTPS   bool          // Enable HTTPS/TLS
	TLSCertFile   string        // TLS certificate file path
	TLSKeyFile    string        // TLS private key file path
	EnableCORS    bool          // Enable Cross-Origin Resource Sharing
	AllowedOrigins []string     // List of allowed CORS origins

	// Rate limiting configuration
	EnableRateLimit bool        // Enable request rate limiting
	RateLimitRPS    int         // Requests per second limit
	RateLimitBurst  int         // Burst size for rate limiting

	// Logging configuration
	LogLevel      string        // Log level: debug, info, warn, error
	LogFormat     string        // Log format: json, text
	LogOutput     string        // Log output: stdout, stderr, file
	LogFile       string        // Log file path (if LogOutput is "file")
}

/*
LOADCONFIG FUNCTION
Main configuration loading function that orchestrates the configuration process
This function demonstrates Go's error handling pattern and configuration validation
*/
func LoadConfig() (*Config, error) {
	// Create new Config instance with default values
	config := &Config{
		// Set default values for configuration
		ServerPort:        getEnvOrDefault("SERVER_PORT", "8080"),
		ServerHost:        getEnvOrDefault("SERVER_HOST", "localhost"),
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		AppName:          getEnvOrDefault("APP_NAME", "ScholasticGoTutorial"),
		DebugMode:        getEnvBoolOrDefault("DEBUG_MODE", false),
		Environment:      getEnvOrDefault("ENVIRONMENT", "development"),
		DBHost:           getEnvOrDefault("DB_HOST", "localhost"),
		DBPort:           getEnvOrDefault("DB_PORT", "5432"),
		DBName:           getEnvOrDefault("DB_NAME", "scholastic_go"),
		DBUser:           getEnvOrDefault("DB_USER", "postgres"),
		DBPassword:       getEnvOrDefault("DB_PASSWORD", ""),
		DBMaxConns:       getEnvIntOrDefault("DB_MAX_CONNS", 25),
		DBMaxIdle:        getEnvIntOrDefault("DB_MAX_IDLE", 5),
		WSReadBufferSize:  getEnvIntOrDefault("WS_READ_BUFFER_SIZE", 1024),
		WSWriteBufferSize: getEnvIntOrDefault("WS_WRITE_BUFFER_SIZE", 1024),
		WSPingPeriod:      54 * time.Second,
		EnableHTTPS:       getEnvBoolOrDefault("ENABLE_HTTPS", false),
		TLSCertFile:       getEnvOrDefault("TLS_CERT_FILE", ""),
		TLSKeyFile:        getEnvOrDefault("TLS_KEY_FILE", ""),
		EnableCORS:        getEnvBoolOrDefault("ENABLE_CORS", true),
		AllowedOrigins:    getEnvStringSliceOrDefault("ALLOWED_ORIGINS", []string{"*"}),
		EnableRateLimit:   getEnvBoolOrDefault("ENABLE_RATE_LIMIT", false),
		RateLimitRPS:      getEnvIntOrDefault("RATE_LIMIT_RPS", 10),
		RateLimitBurst:    getEnvIntOrDefault("RATE_LIMIT_BURST", 20),
		LogLevel:          getEnvOrDefault("LOG_LEVEL", "info"),
		LogFormat:         getEnvOrDefault("LOG_FORMAT", "text"),
		LogOutput:         getEnvOrDefault("LOG_OUTPUT", "stdout"),
		LogFile:           getEnvOrDefault("LOG_FILE", ""),
	}

	/*
	ENVIRONMENT-SPECIFIC CONFIGURATION
	Override defaults based on environment
	This demonstrates how to handle different deployment environments
	*/
	switch config.Environment {
	case "production":
		// Production-specific settings
		config.DebugMode = false                                    // Disable debug mode in production
		config.LogLevel = "warn"                                    // Higher log level for production
		config.EnableRateLimit = true                               // Enable rate limiting
		config.EnableHTTPS = true                                   // Force HTTPS in production
		config.AllowedOrigins = []string{"https://example.com"}     // Restrict CORS origins
		
		// Override with production environment variables if set
		if !getEnvBoolOrDefault("DEBUG_MODE", false) {
			config.DebugMode = false
		}
		
	case "development":
		// Development-specific settings
		config.DebugMode = true                                     // Enable debug mode
		config.LogLevel = "debug"                                   // Verbose logging
		config.EnableCORS = true                                    // Enable CORS for development
		config.AllowedOrigins = []string{"*"}                       // Allow all origins
		config.ReadTimeout = 30 * time.Second                       // Longer timeouts for debugging
		
	case "testing":
		// Testing-specific settings
		config.DebugMode = true                                     // Debug mode for tests
		config.LogLevel = "debug"                                   // Verbose logging
		config.ServerPort = getEnvOrDefault("SERVER_PORT", "8081")  // Different port for testing
	}

	/*
	CONFIGURATION VALIDATION
	Validate configuration values for correctness
	This demonstrates Go's approach to input validation
	*/
	if err := config.Validate(); err != nil {
		// Return validation error with detailed message
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Configuration loaded successfully
	return config, nil
}

/*
VALIDATE METHOD
Validate configuration values to ensure they are reasonable and safe
This method demonstrates Go's approach to defensive programming
*/
func (c *Config) Validate() error {
	// Validate server port
	if c.ServerPort == "" {
		return fmt.Errorf("server port cannot be empty")
	}
	
	// Validate port number range (1-65535)
	portNum := 0
	if _, err := fmt.Sscanf(c.ServerPort, "%d", &portNum); err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid server port: %s (must be between 1-65535)", c.ServerPort)
	}

	// Validate timeouts
	if c.ReadTimeout <= 0 {
		return fmt.Errorf("read timeout must be positive, got: %v", c.ReadTimeout)
	}
	if c.WriteTimeout <= 0 {
		return fmt.Errorf("write timeout must be positive, got: %v", c.WriteTimeout)
	}
	if c.IdleTimeout <= 0 {
		return fmt.Errorf("idle timeout must be positive, got: %v", c.IdleTimeout)
	}

	// Validate environment
	validEnvironments := []string{"development", "staging", "production", "testing"}
	if !contains(validEnvironments, c.Environment) {
		return fmt.Errorf("invalid environment: %s (must be one of: %v)", c.Environment, validEnvironments)
	}

	// Validate log level
	validLogLevels := []string{"debug", "info", "warn", "error"}
	if !contains(validLogLevels, c.LogLevel) {
		return fmt.Errorf("invalid log level: %s (must be one of: %v)", c.LogLevel, validLogLevels)
	}

	// Validate database configuration if database is enabled
	if c.DBHost != "" {
		if c.DBPort == "" {
			return fmt.Errorf("database port cannot be empty when host is specified")
		}
		if c.DBName == "" {
			return fmt.Errorf("database name cannot be empty")
		}
		if c.DBMaxConns <= 0 {
			return fmt.Errorf("database max connections must be positive, got: %d", c.DBMaxConns)
		}
		if c.DBMaxIdle < 0 {
			return fmt.Errorf("database max idle connections cannot be negative, got: %d", c.DBMaxIdle)
		}
	}

	// Validate WebSocket configuration
	if c.WSReadBufferSize <= 0 {
		return fmt.Errorf("WebSocket read buffer size must be positive, got: %d", c.WSReadBufferSize)
	}
	if c.WSWriteBufferSize <= 0 {
		return fmt.Errorf("WebSocket write buffer size must be positive, got: %d", c.WSWriteBufferSize)
	}
	if c.WSPingPeriod <= 0 {
		return fmt.Errorf("WebSocket ping period must be positive, got: %v", c.WSPingPeriod)
	}

	// Validate TLS configuration if HTTPS is enabled
	if c.EnableHTTPS {
		if c.TLSCertFile == "" {
			return fmt.Errorf("TLS certificate file is required when HTTPS is enabled")
		}
		if c.TLSKeyFile == "" {
			return fmt.Errorf("TLS key file is required when HTTPS is enabled")
		}
		
		// Check if certificate files exist
		if _, err := os.Stat(c.TLSCertFile); os.IsNotExist(err) {
			return fmt.Errorf("TLS certificate file not found: %s", c.TLSCertFile)
		}
		if _, err := os.Stat(c.TLSKeyFile); os.IsNotExist(err) {
			return fmt.Errorf("TLS key file not found: %s", c.TLSKeyFile)
		}
	}

	// Validate rate limiting configuration
	if c.EnableRateLimit {
		if c.RateLimitRPS <= 0 {
			return fmt.Errorf("rate limit requests per second must be positive, got: %d", c.RateLimitRPS)
		}
		if c.RateLimitBurst <= 0 {
			return fmt.Errorf("rate limit burst size must be positive, got: %d", c.RateLimitBurst)
		}
	}

	// All validations passed
	return nil
}

/*
STRING REPRESENTATION
Provide string representation of configuration (without sensitive data)
This is useful for logging configuration without exposing secrets
*/
func (c *Config) String() string {
	return fmt.Sprintf(
		"Config{ServerPort: %s, Environment: %s, DebugMode: %t, AppName: %s, LogLevel: %s}",
		c.ServerPort,
		c.Environment,
		c.DebugMode,
		c.AppName,
		c.LogLevel,
	)
}

/*
HELPER FUNCTIONS
Utility functions for configuration loading
These demonstrate Go's approach to code reuse and helper functions
*/

// getEnvOrDefault retrieves environment variable or returns default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvBoolOrDefault retrieves boolean environment variable or returns default
func getEnvBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// getEnvIntOrDefault retrieves integer environment variable or returns default
func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// getEnvStringSliceOrDefault retrieves comma-separated environment variable as string slice
func getEnvStringSliceOrDefault(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		// Split by comma and trim whitespace from each element
		parts := strings.Split(value, ",")
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				result = append(result, trimmed)
			}
		}
		return result
	}
	return defaultValue
}

// contains checks if a string slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
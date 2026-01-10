package errors

import (
	"fmt"
	"strings"
)

// ErrorCode represents different error categories
type ErrorCode string

const (
	ErrMissingArgument   ErrorCode = "MISSING_ARGUMENT"
	ErrInvalidArgument   ErrorCode = "INVALID_ARGUMENT"
	ErrMissingDependency ErrorCode = "MISSING_DEPENDENCY"
	ErrConfigError       ErrorCode = "CONFIG_ERROR"
	ErrPolicyError       ErrorCode = "POLICY_ERROR"
	ErrScanError         ErrorCode = "SCAN_ERROR"
	ErrParseError        ErrorCode = "PARSE_ERROR"
	ErrDatabaseError     ErrorCode = "DATABASE_ERROR"
	ErrNetworkError      ErrorCode = "NETWORK_ERROR"
	ErrPermissionError   ErrorCode = "PERMISSION_ERROR"
	ErrNotFound          ErrorCode = "NOT_FOUND"
	ErrValidationFailed  ErrorCode = "VALIDATION_FAILED"
)

// SentinelError represents a structured error with helpful context
type SentinelError struct {
	Code       ErrorCode
	Message    string
	Detail     string
	Suggestion string
	Command    string
	Example    string
}

func (e *SentinelError) Error() string {
	var sb strings.Builder

	// Error header with code
	sb.WriteString(fmt.Sprintf("\033[31mError [%s]:\033[0m %s\n", e.Code, e.Message))

	// Detail if provided
	if e.Detail != "" {
		sb.WriteString(fmt.Sprintf("\n\033[33mDetail:\033[0m %s\n", e.Detail))
	}

	// Suggestion if provided
	if e.Suggestion != "" {
		sb.WriteString(fmt.Sprintf("\n\033[36mSuggestion:\033[0m %s\n", e.Suggestion))
	}

	// Example if provided
	if e.Example != "" {
		sb.WriteString(fmt.Sprintf("\n\033[32mExample:\033[0m\n  %s\n", e.Example))
	}

	return sb.String()
}

// New creates a new SentinelError
func New(code ErrorCode, message string) *SentinelError {
	return &SentinelError{
		Code:    code,
		Message: message,
	}
}

// WithDetail adds detail to the error
func (e *SentinelError) WithDetail(detail string) *SentinelError {
	e.Detail = detail
	return e
}

// WithSuggestion adds a suggestion to the error
func (e *SentinelError) WithSuggestion(suggestion string) *SentinelError {
	e.Suggestion = suggestion
	return e
}

// WithExample adds an example to the error
func (e *SentinelError) WithExample(example string) *SentinelError {
	e.Example = example
	return e
}

// WithCommand adds the command context to the error
func (e *SentinelError) WithCommand(cmd string) *SentinelError {
	e.Command = cmd
	return e
}

// Common error constructors

// MissingArgument creates an error for missing required arguments
func MissingArgument(argName, command string) *SentinelError {
	return &SentinelError{
		Code:       ErrMissingArgument,
		Message:    fmt.Sprintf("Missing required argument: %s", argName),
		Command:    command,
		Suggestion: fmt.Sprintf("Run 'sentinel %s --help' for usage information", command),
	}
}

// MissingDockerCommand creates an error when no docker command is provided
func MissingDockerCommand(command string) *SentinelError {
	return &SentinelError{
		Code:       ErrMissingArgument,
		Message:    "No docker command provided",
		Detail:     "The command requires a docker command to be specified after '--'",
		Suggestion: "Provide a docker command after the '--' separator",
		Example:    fmt.Sprintf("sentinel %s -- docker run nginx:latest", command),
	}
}

// InvalidArgument creates an error for invalid argument values
func InvalidArgument(argName, value, reason string) *SentinelError {
	return &SentinelError{
		Code:    ErrInvalidArgument,
		Message: fmt.Sprintf("Invalid value for '%s': %s", argName, value),
		Detail:  reason,
	}
}

// InvalidFlag creates an error for invalid flag values
func InvalidFlag(flagName, value string, validValues []string) *SentinelError {
	return &SentinelError{
		Code:       ErrInvalidArgument,
		Message:    fmt.Sprintf("Invalid value '%s' for flag '--%s'", value, flagName),
		Detail:     fmt.Sprintf("Valid values are: %s", strings.Join(validValues, ", ")),
		Suggestion: fmt.Sprintf("Use one of the valid values for --%s", flagName),
	}
}

// MissingDependency creates an error for missing external dependencies
func MissingDependency(dep, purpose string, installInstructions []string) *SentinelError {
	return &SentinelError{
		Code:       ErrMissingDependency,
		Message:    fmt.Sprintf("Required dependency not found: %s", dep),
		Detail:     fmt.Sprintf("%s is required for %s", dep, purpose),
		Suggestion: fmt.Sprintf("Install %s using one of the following methods:\n  %s", dep, strings.Join(installInstructions, "\n  ")),
	}
}

// ConfigError creates an error for configuration issues
func ConfigError(message, configPath string) *SentinelError {
	return &SentinelError{
		Code:       ErrConfigError,
		Message:    message,
		Detail:     fmt.Sprintf("Configuration file: %s", configPath),
		Suggestion: "Check your configuration file for syntax errors or missing fields",
	}
}

// PolicyNotFound creates an error when a policy file is not found
func PolicyNotFound(policyName, policyDir string) *SentinelError {
	return &SentinelError{
		Code:       ErrNotFound,
		Message:    fmt.Sprintf("Policy '%s' not found", policyName),
		Detail:     fmt.Sprintf("Expected location: %s/%s.yaml", policyDir, policyName),
		Suggestion: "Use 'sentinel policy list' to see available policies or create a new policy file",
	}
}

// PolicyLoadError creates an error when a policy fails to load
func PolicyLoadError(policyName string, err error) *SentinelError {
	return &SentinelError{
		Code:       ErrPolicyError,
		Message:    fmt.Sprintf("Failed to load policy '%s'", policyName),
		Detail:     err.Error(),
		Suggestion: "Check the policy file for YAML syntax errors",
	}
}

// ImageNotFound creates an error when a docker image is not found
func ImageNotFound(image string) *SentinelError {
	return &SentinelError{
		Code:       ErrNotFound,
		Message:    fmt.Sprintf("Image '%s' not found", image),
		Suggestion: "Ensure the image exists locally or can be pulled from a registry",
		Example:    fmt.Sprintf("docker pull %s", image),
	}
}

// ScanFailed creates an error when a scan operation fails
func ScanFailed(scanner, image string, err error) *SentinelError {
	return &SentinelError{
		Code:       ErrScanError,
		Message:    fmt.Sprintf("Scan failed using %s", scanner),
		Detail:     fmt.Sprintf("Image: %s\nError: %v", image, err),
		Suggestion: fmt.Sprintf("Ensure %s is installed and the image exists", scanner),
	}
}

// DatabaseError creates an error for database operations
func DatabaseError(operation string, err error) *SentinelError {
	return &SentinelError{
		Code:       ErrDatabaseError,
		Message:    fmt.Sprintf("Database operation failed: %s", operation),
		Detail:     err.Error(),
		Suggestion: "Check if the audit database is accessible and not corrupted",
	}
}

// ParseError creates an error for command parsing failures
func ParseError(input string, err error) *SentinelError {
	return &SentinelError{
		Code:       ErrParseError,
		Message:    "Failed to parse docker command",
		Detail:     fmt.Sprintf("Input: %s\nError: %v", input, err),
		Suggestion: "Ensure the docker command syntax is correct",
	}
}

// NoResults creates an error when a query returns no results
func NoResults(query string) *SentinelError {
	return &SentinelError{
		Code:       ErrNotFound,
		Message:    "No results found",
		Detail:     fmt.Sprintf("Query: %s", query),
		Suggestion: "Try broadening your search criteria",
	}
}

// PermissionDenied creates an error for permission issues
func PermissionDenied(resource, action string) *SentinelError {
	return &SentinelError{
		Code:       ErrPermissionError,
		Message:    fmt.Sprintf("Permission denied: cannot %s %s", action, resource),
		Suggestion: "Check file permissions or run with appropriate privileges",
	}
}

// Wrap wraps a standard error with SentinelError context
func Wrap(err error, code ErrorCode, message string) *SentinelError {
	return &SentinelError{
		Code:    code,
		Message: message,
		Detail:  err.Error(),
	}
}

// FormatValidationErrors formats multiple validation errors
func FormatValidationErrors(errors []string) string {
	if len(errors) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\033[31mValidation errors:\033[0m\n")
	for i, err := range errors {
		sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, err))
	}
	return sb.String()
}

// PrintUsageHint prints a usage hint for a command
func PrintUsageHint(command, description string, examples []string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n\033[36mUsage:\033[0m sentinel %s\n", command))
	if description != "" {
		sb.WriteString(fmt.Sprintf("\n%s\n", description))
	}
	if len(examples) > 0 {
		sb.WriteString("\n\033[32mExamples:\033[0m\n")
		for _, ex := range examples {
			sb.WriteString(fmt.Sprintf("  %s\n", ex))
		}
	}
	sb.WriteString(fmt.Sprintf("\nRun 'sentinel %s --help' for more information.\n", strings.Split(command, " ")[0]))
	return sb.String()
}

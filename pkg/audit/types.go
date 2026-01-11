package audit

import (
	"time"
)

// Decision represents the authorization decision
type Decision string

const (
	DecisionAllowed Decision = "allowed"
	DecisionDenied  Decision = "denied"
	DecisionWarned  Decision = "warned"
)

// Entry represents a single audit log entry
type Entry struct {
	// ID is the unique identifier (auto-generated for SQLite)
	ID int64 `json:"id,omitempty"`

	// Timestamp is when the request was received
	Timestamp time.Time `json:"timestamp"`

	// User is the Docker client user (from AuthZRequest.User)
	User string `json:"user"`

	// Method is the HTTP method (GET, POST, DELETE, etc.)
	Method string `json:"method"`

	// URI is the Docker API endpoint (e.g., /v1.47/containers/create)
	URI string `json:"uri"`

	// Image is the container image if applicable
	Image string `json:"image,omitempty"`

	// Command is a reconstructed docker command summary
	Command string `json:"command,omitempty"`

	// RiskScore is the calculated risk score (0-100)
	RiskScore int `json:"risk_score"`

	// Decision is the authorization decision (allowed, denied, warned)
	Decision Decision `json:"decision"`

	// Reason contains the denial reason or warnings
	Reason string `json:"reason,omitempty"`

	// DurationMs is the processing time in milliseconds
	DurationMs int64 `json:"duration_ms"`

	// Policy is the active policy name at time of decision
	Policy string `json:"policy"`

	// Violations is the list of policy violations (for denied/warned)
	Violations []string `json:"violations,omitempty"`
}

// QueryOptions contains options for querying audit entries
type QueryOptions struct {
	// Since filters entries after this time
	Since *time.Time

	// Until filters entries before this time
	Until *time.Time

	// User filters by username
	User string

	// Decision filters by decision type
	Decision Decision

	// Limit is the maximum number of entries to return
	Limit int

	// Offset is the number of entries to skip (for pagination)
	Offset int

	// OrderDesc orders by timestamp descending (newest first)
	OrderDesc bool
}

// Stats contains aggregated statistics
type Stats struct {
	// TotalRequests is the total number of requests
	TotalRequests int64 `json:"total_requests"`

	// AllowedCount is the number of allowed requests
	AllowedCount int64 `json:"allowed_count"`

	// DeniedCount is the number of denied requests
	DeniedCount int64 `json:"denied_count"`

	// WarnedCount is the number of warned requests
	WarnedCount int64 `json:"warned_count"`

	// UniqueUsers is the number of unique users
	UniqueUsers int64 `json:"unique_users"`

	// TopUsers is a list of users with most requests
	TopUsers []UserStat `json:"top_users,omitempty"`

	// TopDeniedReasons is a list of most common denial reasons
	TopDeniedReasons []ReasonStat `json:"top_denied_reasons,omitempty"`

	// AvgRiskScore is the average risk score
	AvgRiskScore float64 `json:"avg_risk_score"`

	// AvgDurationMs is the average processing time
	AvgDurationMs float64 `json:"avg_duration_ms"`

	// Since is the start of the stats period
	Since time.Time `json:"since"`

	// Until is the end of the stats period
	Until time.Time `json:"until"`
}

// UserStat contains statistics for a single user
type UserStat struct {
	User    string `json:"user"`
	Count   int64  `json:"count"`
	Denied  int64  `json:"denied"`
	Allowed int64  `json:"allowed"`
}

// ReasonStat contains statistics for a denial reason
type ReasonStat struct {
	Reason string `json:"reason"`
	Count  int64  `json:"count"`
}

// ExportFormat represents the export format
type ExportFormat string

const (
	ExportFormatJSON ExportFormat = "json"
	ExportFormatCSV  ExportFormat = "csv"
)


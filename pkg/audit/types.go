package audit

import (
	"time"
)

// Entry represents a single audited Docker API request
type Entry struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	User       string    `json:"user"`
	Method     string    `json:"method"`
	URI        string    `json:"uri"`
	Image      string    `json:"image,omitempty"`
	Command    string    `json:"command,omitempty"`
	RiskScore  int       `json:"risk_score"`
	Decision   Decision  `json:"decision"`
	Reason     string    `json:"reason,omitempty"`
	DurationMs int64     `json:"duration_ms"`
	Policy     string    `json:"policy,omitempty"`
	Violations []string  `json:"violations,omitempty"`
}

// Decision represents the authorization decision
type Decision string

const (
	DecisionAllowed Decision = "allowed"
	DecisionDenied  Decision = "denied"
	DecisionWarned  Decision = "warned"
)

// QueryOptions for filtering audit logs
type QueryOptions struct {
	Since    time.Time
	Until    time.Time
	User     string
	Decision Decision
	Limit    int
	Offset   int
}

// Stats represents summary statistics for audit logs
type Stats struct {
	TotalRequests int       `json:"total_requests"`
	Allowed       int       `json:"allowed"`
	Denied        int       `json:"denied"`
	Warned        int       `json:"warned"`
	AvgRiskScore  float64   `json:"avg_risk_score"`
	AvgDurationMs float64   `json:"avg_duration_ms"`
	UniqueUsers   int       `json:"unique_users"`
	TopUsers      []UserStat   `json:"top_users"`
	TopDenials    []ReasonStat `json:"top_denials"`
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"end_time"`
}

// UserStat represents statistics for a single user
type UserStat struct {
	Name     string `json:"name"`
	Requests int    `json:"requests"`
	Denied   int    `json:"denied"`
}

// ReasonStat represents statistics for a denial reason
type ReasonStat struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}


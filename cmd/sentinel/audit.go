package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rtvkiz/docker-sentinel/pkg/audit"
	serrors "github.com/rtvkiz/docker-sentinel/pkg/errors"
	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "View and manage audit logs",
	Long: `View and manage Docker Sentinel audit logs.

The audit system logs all Docker API requests intercepted by the authorization
plugin, including who made the request, what command was executed, and the
authorization decision.

Examples:
  sentinel audit list                    # View recent audit entries
  sentinel audit list --decision denied  # View denied requests
  sentinel audit tail                    # Live tail of audit log
  sentinel audit stats --since 7d        # View statistics for last 7 days
  sentinel audit export --format csv     # Export to CSV`,
}

var auditListCmd = &cobra.Command{
	Use:   "list",
	Short: "List audit entries",
	Long: `List audit entries with optional filtering.

Examples:
  sentinel audit list                       # View recent entries (default 50)
  sentinel audit list --limit 100           # View last 100 entries
  sentinel audit list --decision denied     # View only denied requests
  sentinel audit list --user root           # View requests from root user
  sentinel audit list --since 24h           # View entries from last 24 hours`,
	RunE:          runAuditList,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var auditTailCmd = &cobra.Command{
	Use:   "tail",
	Short: "Live tail of audit log",
	Long: `Watch the audit log in real-time, similar to 'tail -f'.

Examples:
  sentinel audit tail             # Tail the log
  sentinel audit tail --lines 20  # Show last 20 lines first`,
	RunE:          runAuditTail,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var auditExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export audit logs",
	Long: `Export audit logs to CSV or JSON format.

Examples:
  sentinel audit export --format csv --output /tmp/audit.csv
  sentinel audit export --format json --since 7d --output /tmp/audit.json
  sentinel audit export --format csv  # Output to stdout`,
	RunE:          runAuditExport,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var auditStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show audit statistics",
	Long: `Show aggregated statistics from audit logs.

Examples:
  sentinel audit stats           # Overall statistics
  sentinel audit stats --since 7d  # Statistics for last 7 days
  sentinel audit stats --since 24h # Statistics for last 24 hours`,
	RunE:          runAuditStats,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var auditClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear old audit entries",
	Long: `Remove audit entries older than a specified time.

Examples:
  sentinel audit clear --keep-days 30  # Keep last 30 days
  sentinel audit clear --before 2024-01-01
  sentinel audit clear --keep-days 7 --force  # Skip confirmation`,
	RunE:          runAuditClear,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	// List flags
	auditListCmd.Flags().Int("limit", 50, "Maximum number of entries to show")
	auditListCmd.Flags().String("since", "", "Show entries after this time (e.g., 24h, 7d, 2024-01-01)")
	auditListCmd.Flags().String("until", "", "Show entries before this time")
	auditListCmd.Flags().String("user", "", "Filter by username")
	auditListCmd.Flags().String("decision", "", "Filter by decision (allowed, denied, warned)")

	// Tail flags
	auditTailCmd.Flags().Int("lines", 10, "Number of lines to show initially")

	// Export flags
	auditExportCmd.Flags().String("format", "json", "Export format (json, csv)")
	auditExportCmd.Flags().String("output", "", "Output file (default: stdout)")
	auditExportCmd.Flags().String("since", "", "Export entries after this time")
	auditExportCmd.Flags().String("until", "", "Export entries before this time")

	// Stats flags
	auditStatsCmd.Flags().String("since", "", "Statistics start time")
	auditStatsCmd.Flags().String("until", "", "Statistics end time")

	// Clear flags
	auditClearCmd.Flags().Int("keep-days", 0, "Number of days to keep")
	auditClearCmd.Flags().String("before", "", "Delete entries before this date")
	auditClearCmd.Flags().Bool("force", false, "Skip confirmation prompt")

	// Add subcommands
	auditCmd.AddCommand(auditListCmd)
	auditCmd.AddCommand(auditTailCmd)
	auditCmd.AddCommand(auditExportCmd)
	auditCmd.AddCommand(auditStatsCmd)
	auditCmd.AddCommand(auditClearCmd)
}

// getAuditStore opens the audit SQLite store
func getAuditStore() (*audit.Store, error) {
	auditDir := audit.GetDefaultAuditDir(cfg.ConfigDir)
	store, err := audit.NewStore(auditDir)
	if err != nil {
		return nil, serrors.New(serrors.ErrConfigError, "Failed to open audit database").
			WithDetail(err.Error()).
			WithSuggestion("Ensure the audit directory exists and is writable")
	}
	return store, nil
}

// parseTimeFlag parses a time flag value
func parseTimeFlag(value string) (*time.Time, error) {
	if value == "" {
		return nil, nil
	}

	// Try duration format (e.g., "24h", "7d")
	if strings.HasSuffix(value, "h") || strings.HasSuffix(value, "m") || strings.HasSuffix(value, "s") {
		d, err := time.ParseDuration(value)
		if err == nil {
			t := time.Now().Add(-d)
			return &t, nil
		}
	}

	// Try day format (e.g., "7d")
	if strings.HasSuffix(value, "d") {
		days := 0
		if _, err := fmt.Sscanf(value, "%dd", &days); err == nil {
			t := time.Now().AddDate(0, 0, -days)
			return &t, nil
		}
	}

	// Try date format
	formats := []string{
		"2006-01-02",
		"2006-01-02T15:04:05",
		time.RFC3339,
	}
	for _, format := range formats {
		t, err := time.Parse(format, value)
		if err == nil {
			return &t, nil
		}
	}

	return nil, fmt.Errorf("invalid time format: %s", value)
}

func runAuditList(cmd *cobra.Command, args []string) error {
	store, err := getAuditStore()
	if err != nil {
		return err
	}
	defer store.Close()

	limit, _ := cmd.Flags().GetInt("limit")
	sinceStr, _ := cmd.Flags().GetString("since")
	untilStr, _ := cmd.Flags().GetString("until")
	user, _ := cmd.Flags().GetString("user")
	decisionStr, _ := cmd.Flags().GetString("decision")

	since, err := parseTimeFlag(sinceStr)
	if err != nil {
		return serrors.New(serrors.ErrInvalidArgument, "Invalid --since value").WithDetail(err.Error())
	}

	until, err := parseTimeFlag(untilStr)
	if err != nil {
		return serrors.New(serrors.ErrInvalidArgument, "Invalid --until value").WithDetail(err.Error())
	}

	opts := audit.QueryOptions{
		Since:     since,
		Until:     until,
		User:      user,
		Decision:  audit.Decision(decisionStr),
		Limit:     limit,
		OrderDesc: true,
	}

	entries, err := store.Query(opts)
	if err != nil {
		return serrors.New(serrors.ErrDatabaseError, "Failed to query audit entries").WithDetail(err.Error())
	}

	if len(entries) == 0 {
		fmt.Println("No audit entries found.")
		return nil
	}

	// Print header
	fmt.Println()
	fmt.Printf("%-20s %-12s %-8s %-6s %s\n", "TIMESTAMP", "USER", "DECISION", "SCORE", "COMMAND")
	fmt.Println(strings.Repeat("-", 110))

	for _, entry := range entries {
		user := entry.User
		if user == "" {
			user = "(unknown)"
		}
		if len(user) > 12 {
			user = user[:11] + "…"
		}

		// Use Command if available, otherwise show URI
		command := entry.Command
		if command == "" {
			command = entry.Method + " " + entry.URI
		}
		if len(command) > 60 {
			command = command[:57] + "..."
		}

		decisionColor := "\033[32m" // green for allowed
		if entry.Decision == audit.DecisionDenied {
			decisionColor = "\033[31m" // red for denied
		} else if entry.Decision == audit.DecisionWarned {
			decisionColor = "\033[33m" // yellow for warned
		}

		fmt.Printf("%-20s %-12s %s%-8s\033[0m %-6d %s\n",
			entry.Timestamp.Format("2006-01-02 15:04:05"),
			user,
			decisionColor,
			entry.Decision,
			entry.RiskScore,
			command,
		)
	}

	fmt.Printf("\nShowing %d entries\n", len(entries))
	return nil
}

func runAuditTail(cmd *cobra.Command, args []string) error {
	auditDir := audit.GetDefaultAuditDir(cfg.ConfigDir)
	jsonPath := auditDir + "/audit.jsonl"

	// Check if file exists
	if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
		return serrors.New(serrors.ErrNotFound, "Audit log file not found").
			WithDetail(jsonPath).
			WithSuggestion("Ensure the authorization plugin is running with audit enabled")
	}

	lines, _ := cmd.Flags().GetInt("lines")

	fmt.Printf("Tailing %s (press Ctrl+C to stop)\n", jsonPath)
	fmt.Println(strings.Repeat("-", 80))

	// Show last N lines first
	if lines > 0 {
		if err := showLastLines(jsonPath, lines); err != nil {
			fmt.Printf("Warning: could not show initial lines: %v\n", err)
		}
	}

	// Open file for tailing
	file, err := os.Open(jsonPath)
	if err != nil {
		return serrors.New(serrors.ErrDatabaseError, "Failed to open audit log").WithDetail(err.Error())
	}
	defer file.Close()

	// Seek to end
	file.Seek(0, io.SeekEnd)

	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return err
		}

		// Parse and format the entry
		var entry audit.Entry
		if err := json.Unmarshal([]byte(line), &entry); err == nil {
			printAuditEntry(&entry)
		}
	}
}

func showLastLines(path string, n int) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Read all lines (simple approach for small files)
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// Show last n lines
	start := len(lines) - n
	if start < 0 {
		start = 0
	}

	for i := start; i < len(lines); i++ {
		var entry audit.Entry
		if err := json.Unmarshal([]byte(lines[i]), &entry); err == nil {
			printAuditEntry(&entry)
		}
	}

	return nil
}

func printAuditEntry(entry *audit.Entry) {
	decisionColor := "\033[32m" // green
	decisionIcon := "✓"
	if entry.Decision == audit.DecisionDenied {
		decisionColor = "\033[31m" // red
		decisionIcon = "✗"
	} else if entry.Decision == audit.DecisionWarned {
		decisionColor = "\033[33m" // yellow
		decisionIcon = "⚠"
	}

	user := entry.User
	if user == "" {
		user = "(unknown)"
	}

	// Use Command if available, otherwise show Method + URI
	command := entry.Command
	if command == "" {
		command = entry.Method + " " + entry.URI
	}

	fmt.Printf("%s%s\033[0m [%s] %s: %s (score: %d, %dms)\n",
		decisionColor,
		decisionIcon,
		entry.Timestamp.Format("15:04:05"),
		user,
		command,
		entry.RiskScore,
		entry.DurationMs,
	)
}

func runAuditExport(cmd *cobra.Command, args []string) error {
	store, err := getAuditStore()
	if err != nil {
		return err
	}
	defer store.Close()

	format, _ := cmd.Flags().GetString("format")
	output, _ := cmd.Flags().GetString("output")
	sinceStr, _ := cmd.Flags().GetString("since")
	untilStr, _ := cmd.Flags().GetString("until")

	since, err := parseTimeFlag(sinceStr)
	if err != nil {
		return serrors.New(serrors.ErrInvalidArgument, "Invalid --since value").WithDetail(err.Error())
	}

	until, err := parseTimeFlag(untilStr)
	if err != nil {
		return serrors.New(serrors.ErrInvalidArgument, "Invalid --until value").WithDetail(err.Error())
	}

	opts := audit.QueryOptions{
		Since:     since,
		Until:     until,
		OrderDesc: false, // chronological order for export
	}

	entries, err := store.Query(opts)
	if err != nil {
		return serrors.New(serrors.ErrDatabaseError, "Failed to query audit entries").WithDetail(err.Error())
	}

	// Determine output destination
	var w io.Writer = os.Stdout
	if output != "" {
		file, err := os.Create(output)
		if err != nil {
			return serrors.New(serrors.ErrDatabaseError, "Failed to create output file").WithDetail(err.Error())
		}
		defer file.Close()
		w = file
	}

	switch format {
	case "json":
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(entries); err != nil {
			return serrors.New(serrors.ErrDatabaseError, "Failed to encode JSON").WithDetail(err.Error())
		}

	case "csv":
		csvWriter := csv.NewWriter(w)
		defer csvWriter.Flush()

		// Write header
		csvWriter.Write([]string{
			"timestamp", "user", "method", "uri", "image", "command",
			"risk_score", "decision", "reason", "duration_ms", "policy",
		})

		// Write rows
		for _, entry := range entries {
			csvWriter.Write([]string{
				entry.Timestamp.Format(time.RFC3339),
				entry.User,
				entry.Method,
				entry.URI,
				entry.Image,
				entry.Command,
				fmt.Sprintf("%d", entry.RiskScore),
				string(entry.Decision),
				entry.Reason,
				fmt.Sprintf("%d", entry.DurationMs),
				entry.Policy,
			})
		}

	default:
		return serrors.New(serrors.ErrInvalidArgument, "Invalid format").
			WithDetail("Supported formats: json, csv")
	}

	if output != "" {
		fmt.Printf("Exported %d entries to %s\n", len(entries), output)
	}

	return nil
}

func runAuditStats(cmd *cobra.Command, args []string) error {
	store, err := getAuditStore()
	if err != nil {
		return err
	}
	defer store.Close()

	sinceStr, _ := cmd.Flags().GetString("since")
	untilStr, _ := cmd.Flags().GetString("until")

	since, err := parseTimeFlag(sinceStr)
	if err != nil {
		return serrors.New(serrors.ErrInvalidArgument, "Invalid --since value").WithDetail(err.Error())
	}

	until, err := parseTimeFlag(untilStr)
	if err != nil {
		return serrors.New(serrors.ErrInvalidArgument, "Invalid --until value").WithDetail(err.Error())
	}

	stats, err := store.GetStats(since, until)
	if err != nil {
		return serrors.New(serrors.ErrDatabaseError, "Failed to get statistics").WithDetail(err.Error())
	}

	fmt.Println()
	fmt.Println("Docker Sentinel Audit Statistics")
	fmt.Println(strings.Repeat("=", 50))

	if since != nil {
		fmt.Printf("Period: %s to ", since.Format("2006-01-02 15:04"))
	} else {
		fmt.Print("Period: (all time) to ")
	}
	if until != nil {
		fmt.Println(until.Format("2006-01-02 15:04"))
	} else {
		fmt.Println("now")
	}
	fmt.Println()

	fmt.Println("Request Summary")
	fmt.Println(strings.Repeat("-", 30))
	fmt.Printf("  Total Requests:    %d\n", stats.TotalRequests)
	fmt.Printf("  \033[32mAllowed\033[0m:           %d (%.1f%%)\n",
		stats.AllowedCount,
		percentage(stats.AllowedCount, stats.TotalRequests))
	fmt.Printf("  \033[31mDenied\033[0m:            %d (%.1f%%)\n",
		stats.DeniedCount,
		percentage(stats.DeniedCount, stats.TotalRequests))
	fmt.Printf("  \033[33mWarned\033[0m:            %d (%.1f%%)\n",
		stats.WarnedCount,
		percentage(stats.WarnedCount, stats.TotalRequests))
	fmt.Println()

	fmt.Println("Performance")
	fmt.Println(strings.Repeat("-", 30))
	fmt.Printf("  Avg Risk Score:    %.1f\n", stats.AvgRiskScore)
	fmt.Printf("  Avg Duration:      %.1fms\n", stats.AvgDurationMs)
	fmt.Printf("  Unique Users:      %d\n", stats.UniqueUsers)
	fmt.Println()

	if len(stats.TopUsers) > 0 {
		fmt.Println("Top Users")
		fmt.Println(strings.Repeat("-", 30))
		for i, u := range stats.TopUsers {
			if i >= 5 {
				break
			}
			user := u.User
			if user == "" {
				user = "(unknown)"
			}
			fmt.Printf("  %-15s %5d requests (%d denied)\n", user, u.Count, u.Denied)
		}
		fmt.Println()
	}

	if len(stats.TopDeniedReasons) > 0 {
		fmt.Println("Top Denial Reasons")
		fmt.Println(strings.Repeat("-", 30))
		for i, r := range stats.TopDeniedReasons {
			if i >= 5 {
				break
			}
			reason := r.Reason
			if len(reason) > 50 {
				reason = reason[:47] + "..."
			}
			fmt.Printf("  %5d: %s\n", r.Count, reason)
		}
		fmt.Println()
	}

	return nil
}

func percentage(part, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}

func runAuditClear(cmd *cobra.Command, args []string) error {
	store, err := getAuditStore()
	if err != nil {
		return err
	}
	defer store.Close()

	keepDays, _ := cmd.Flags().GetInt("keep-days")
	beforeStr, _ := cmd.Flags().GetString("before")
	force, _ := cmd.Flags().GetBool("force")

	var before time.Time

	if keepDays > 0 {
		before = time.Now().AddDate(0, 0, -keepDays)
	} else if beforeStr != "" {
		t, err := parseTimeFlag(beforeStr)
		if err != nil {
			return serrors.New(serrors.ErrInvalidArgument, "Invalid --before value").WithDetail(err.Error())
		}
		before = *t
	} else {
		return serrors.New(serrors.ErrMissingArgument, "Must specify --keep-days or --before")
	}

	// Count entries to be deleted
	count, err := store.Count()
	if err != nil {
		return serrors.New(serrors.ErrDatabaseError, "Failed to count entries").WithDetail(err.Error())
	}

	// Query entries before the cutoff to get accurate count
	opts := audit.QueryOptions{
		Until: &before,
	}
	entries, _ := store.Query(opts)
	toDelete := len(entries)

	if toDelete == 0 {
		fmt.Println("No entries to delete.")
		return nil
	}

	fmt.Printf("This will delete %d entries (of %d total) before %s\n",
		toDelete, count, before.Format("2006-01-02 15:04:05"))

	if !force {
		fmt.Print("Continue? [y/N]: ")
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "y" {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	deleted, err := store.DeleteBefore(before)
	if err != nil {
		return serrors.New(serrors.ErrDatabaseError, "Failed to delete entries").WithDetail(err.Error())
	}

	fmt.Printf("✓ Deleted %d audit entries\n", deleted)
	return nil
}


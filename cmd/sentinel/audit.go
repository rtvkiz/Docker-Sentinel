package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rtvkiz/docker-sentinel/pkg/audit"
	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "View and manage audit logs",
	Long:  `View, query, and manage Docker Sentinel audit logs.`,
}

var auditListCmd = &cobra.Command{
	Use:   "list",
	Short: "List recent audit entries",
	RunE:  runAuditList,
}

var auditTailCmd = &cobra.Command{
	Use:   "tail",
	Short: "Live tail of audit events",
	RunE:  runAuditTail,
}

var auditStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show audit statistics",
	RunE:  runAuditStats,
}

var auditExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export audit logs to file",
	RunE:  runAuditExport,
}

var auditClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear old audit entries",
	RunE:  runAuditClear,
}

// Flags
var (
	auditLimit    int
	auditSince    string
	auditUntil    string
	auditUser     string
	auditDecision string
	auditFormat   string
	auditOutput   string
	auditKeepDays int
	auditForce    bool
	auditLines    int
)

func init() {
	// List flags
	auditListCmd.Flags().IntVar(&auditLimit, "limit", 20, "Maximum entries to show")
	auditListCmd.Flags().StringVar(&auditSince, "since", "", "Show entries since (e.g., 1h, 24h, 7d)")
	auditListCmd.Flags().StringVar(&auditUntil, "until", "", "Show entries until")
	auditListCmd.Flags().StringVar(&auditUser, "user", "", "Filter by user")
	auditListCmd.Flags().StringVar(&auditDecision, "decision", "", "Filter by decision (allowed, denied, warned)")

	// Tail flags
	auditTailCmd.Flags().IntVar(&auditLines, "lines", 10, "Initial lines to show")

	// Stats flags
	auditStatsCmd.Flags().StringVar(&auditSince, "since", "24h", "Stats since (e.g., 1h, 24h, 7d)")

	// Export flags
	auditExportCmd.Flags().StringVar(&auditFormat, "format", "json", "Export format (json, csv)")
	auditExportCmd.Flags().StringVar(&auditOutput, "output", "", "Output file (default: stdout)")
	auditExportCmd.Flags().StringVar(&auditSince, "since", "", "Export entries since")
	auditExportCmd.Flags().StringVar(&auditUntil, "until", "", "Export entries until")

	// Clear flags
	auditClearCmd.Flags().IntVar(&auditKeepDays, "keep-days", 30, "Keep entries newer than N days")
	auditClearCmd.Flags().BoolVar(&auditForce, "force", false, "Don't ask for confirmation")

	// Add subcommands
	auditCmd.AddCommand(auditListCmd)
	auditCmd.AddCommand(auditTailCmd)
	auditCmd.AddCommand(auditStatsCmd)
	auditCmd.AddCommand(auditExportCmd)
	auditCmd.AddCommand(auditClearCmd)
}

func getAuditDir() string {
	if cfg == nil {
		return "/etc/sentinel/audit"
	}
	return cfg.ConfigDir + "/audit"
}

func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}

	// Handle days specially
	if strings.HasSuffix(s, "d") {
		days := strings.TrimSuffix(s, "d")
		var d int
		if _, err := fmt.Sscanf(days, "%d", &d); err != nil {
			return 0, err
		}
		return time.Duration(d) * 24 * time.Hour, nil
	}

	return time.ParseDuration(s)
}

func runAuditList(cmd *cobra.Command, args []string) error {
	store, err := audit.OpenStore(getAuditDir())
	if err != nil {
		return fmt.Errorf("failed to open audit store: %w", err)
	}
	defer store.Close()

	opts := audit.QueryOptions{
		Limit: auditLimit,
	}

	if auditSince != "" {
		dur, err := parseDuration(auditSince)
		if err != nil {
			return fmt.Errorf("invalid --since: %w", err)
		}
		opts.Since = time.Now().Add(-dur)
	}

	if auditUntil != "" {
		dur, err := parseDuration(auditUntil)
		if err != nil {
			return fmt.Errorf("invalid --until: %w", err)
		}
		opts.Until = time.Now().Add(-dur)
	}

	if auditUser != "" {
		opts.User = auditUser
	}

	if auditDecision != "" {
		opts.Decision = audit.Decision(auditDecision)
	}

	entries, err := store.Query(opts)
	if err != nil {
		return fmt.Errorf("failed to query audit log: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("No audit entries found.")
		return nil
	}

	// Print header
	fmt.Printf("%-19s %-15s %-8s %5s %-s\n", "TIMESTAMP", "USER", "DECISION", "SCORE", "COMMAND")
	fmt.Println(strings.Repeat("-", 110))

	for _, e := range entries {
		user := e.User
		if user == "" {
			user = "(unknown)"
		}
		if len(user) > 15 {
			user = user[:12] + "..."
		}

		command := e.Command
		if command == "" {
			command = fmt.Sprintf("%s %s", e.Method, e.URI)
		}
		if len(command) > 60 {
			command = command[:57] + "..."
		}

		fmt.Printf("%-19s %-15s %-8s %5d %-s\n",
			e.Timestamp.Format("2006-01-02 15:04:05"),
			user,
			e.Decision,
			e.RiskScore,
			command,
		)
	}

	fmt.Printf("\nShowing %d entries\n", len(entries))
	return nil
}

func runAuditTail(cmd *cobra.Command, args []string) error {
	auditDir := getAuditDir()
	logger, err := audit.NewLogger(auditDir)
	if err != nil {
		return fmt.Errorf("failed to open audit logger: %w", err)
	}
	defer logger.Close()

	// Show initial lines
	entries, err := logger.TailJSON(auditLines)
	if err != nil {
		return fmt.Errorf("failed to read initial entries: %w", err)
	}

	for _, e := range entries {
		printTailEntry(e)
	}

	// Watch for new entries
	ch, cancel, err := logger.WatchJSON()
	if err != nil {
		return fmt.Errorf("failed to start watching: %w", err)
	}
	defer cancel()

	fmt.Println("\n--- Watching for new entries (Ctrl+C to stop) ---")

	// Handle interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case entry, ok := <-ch:
			if !ok {
				return nil
			}
			printTailEntry(entry)
		case <-sigCh:
			fmt.Println("\nStopped.")
			return nil
		}
	}
}

func printTailEntry(e audit.Entry) {
	user := e.User
	if user == "" {
		user = "(unknown)"
	}

	decisionIcon := "✓"
	switch e.Decision {
	case audit.DecisionDenied:
		decisionIcon = "✗"
	case audit.DecisionWarned:
		decisionIcon = "⚠"
	}

	command := e.Command
	if command == "" {
		command = fmt.Sprintf("%s %s", e.Method, e.URI)
	}

	fmt.Printf("[%s] %s %s %-12s %s (score: %d)\n",
		e.Timestamp.Format("15:04:05"),
		decisionIcon,
		e.Decision,
		user,
		command,
		e.RiskScore,
	)
}

func runAuditStats(cmd *cobra.Command, args []string) error {
	store, err := audit.OpenStore(getAuditDir())
	if err != nil {
		return fmt.Errorf("failed to open audit store: %w", err)
	}
	defer store.Close()

	since := time.Now().Add(-24 * time.Hour)
	if auditSince != "" {
		dur, err := parseDuration(auditSince)
		if err != nil {
			return fmt.Errorf("invalid --since: %w", err)
		}
		since = time.Now().Add(-dur)
	}

	stats, err := store.GetStats(since)
	if err != nil {
		return fmt.Errorf("failed to get stats: %w", err)
	}

	fmt.Println("Docker Sentinel Audit Statistics")
	fmt.Println("==================================================")
	fmt.Printf("Period: %s to now\n\n", since.Format("2006-01-02 15:04"))

	fmt.Println("Request Summary")
	fmt.Println("------------------------------")
	fmt.Printf("Total Requests: %d\n", stats.TotalRequests)
	if stats.TotalRequests > 0 {
		fmt.Printf("  Allowed: %d (%.1f%%)\n", stats.Allowed, float64(stats.Allowed)/float64(stats.TotalRequests)*100)
		fmt.Printf("  Denied:  %d (%.1f%%)\n", stats.Denied, float64(stats.Denied)/float64(stats.TotalRequests)*100)
		fmt.Printf("  Warned:  %d (%.1f%%)\n", stats.Warned, float64(stats.Warned)/float64(stats.TotalRequests)*100)
	}

	fmt.Println("\nPerformance")
	fmt.Println("------------------------------")
	fmt.Printf("Avg Risk Score: %.1f\n", stats.AvgRiskScore)
	fmt.Printf("Avg Duration:   %.1fms\n", stats.AvgDurationMs)
	fmt.Printf("Unique Users:   %d\n", stats.UniqueUsers)

	if len(stats.TopUsers) > 0 {
		fmt.Println("\nTop Users")
		fmt.Println("------------------------------")
		for _, u := range stats.TopUsers {
			fmt.Printf("  %-20s %d requests (%d denied)\n", u.Name, u.Requests, u.Denied)
		}
	}

	if len(stats.TopDenials) > 0 {
		fmt.Println("\nTop Denial Reasons")
		fmt.Println("------------------------------")
		for _, r := range stats.TopDenials {
			reason := r.Reason
			if len(reason) > 50 {
				reason = reason[:47] + "..."
			}
			fmt.Printf("  %d: %s\n", r.Count, reason)
		}
	}

	return nil
}

func runAuditExport(cmd *cobra.Command, args []string) error {
	store, err := audit.OpenStore(getAuditDir())
	if err != nil {
		return fmt.Errorf("failed to open audit store: %w", err)
	}
	defer store.Close()

	opts := audit.QueryOptions{
		Limit: 0, // No limit for export
	}

	if auditSince != "" {
		dur, err := parseDuration(auditSince)
		if err != nil {
			return fmt.Errorf("invalid --since: %w", err)
		}
		opts.Since = time.Now().Add(-dur)
	}

	if auditUntil != "" {
		dur, err := parseDuration(auditUntil)
		if err != nil {
			return fmt.Errorf("invalid --until: %w", err)
		}
		opts.Until = time.Now().Add(-dur)
	}

	entries, err := store.Query(opts)
	if err != nil {
		return fmt.Errorf("failed to query audit log: %w", err)
	}

	// Determine output destination
	var out *os.File
	if auditOutput == "" || auditOutput == "-" {
		out = os.Stdout
	} else {
		f, err := os.Create(auditOutput)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	switch auditFormat {
	case "json":
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(entries)

	case "csv":
		writer := csv.NewWriter(out)
		defer writer.Flush()

		// Write header
		writer.Write([]string{
			"timestamp", "user", "method", "uri", "image", "command",
			"risk_score", "decision", "reason", "duration_ms", "policy",
		})

		for _, e := range entries {
			writer.Write([]string{
				e.Timestamp.Format(time.RFC3339),
				e.User,
				e.Method,
				e.URI,
				e.Image,
				e.Command,
				fmt.Sprintf("%d", e.RiskScore),
				string(e.Decision),
				e.Reason,
				fmt.Sprintf("%d", e.DurationMs),
				e.Policy,
			})
		}
		return nil

	default:
		return fmt.Errorf("unknown format: %s (use json or csv)", auditFormat)
	}
}

func runAuditClear(cmd *cobra.Command, args []string) error {
	store, err := audit.OpenStore(getAuditDir())
	if err != nil {
		return fmt.Errorf("failed to open audit store: %w", err)
	}
	defer store.Close()

	before := time.Now().AddDate(0, 0, -auditKeepDays)

	// Get count first
	count, err := store.Count()
	if err != nil {
		return fmt.Errorf("failed to count entries: %w", err)
	}

	if count == 0 {
		fmt.Println("No audit entries to clear.")
		return nil
	}

	if !auditForce {
		fmt.Printf("This will delete entries older than %d days (before %s).\n",
			auditKeepDays, before.Format("2006-01-02"))
		fmt.Print("Continue? [y/N]: ")

		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	deleted, err := store.DeleteBefore(before)
	if err != nil {
		return fmt.Errorf("failed to delete entries: %w", err)
	}

	fmt.Printf("Deleted %d entries.\n", deleted)
	return nil
}


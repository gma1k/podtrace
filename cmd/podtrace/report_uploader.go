package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

func newReportUploaderCmd() *cobra.Command {
	var (
		reportFile     string
		reportToSpec   string
		summaryPath    string
		watchInterval  time.Duration
		maxWaitTimeout time.Duration
	)

	cmd := &cobra.Command{
		Use:   "report-uploader",
		Short: "Sidecar uploader for session diagnose artifacts",
		RunE: func(cmd *cobra.Command, args []string) error {
			if reportFile == "" || reportToSpec == "" {
				return errors.New("--report-file and --report-to are both required")
			}
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			return runReportUploader(ctx, reportUploaderOptions{
				ReportFile:     reportFile,
				SummaryFile:    summaryPath,
				ReportToSpec:   reportToSpec,
				WatchInterval:  watchInterval,
				MaxWaitTimeout: maxWaitTimeout,
			})
		},
	}
	cmd.Flags().StringVar(&reportFile, "report-file", "", "Path to the report file the main container produces")
	cmd.Flags().StringVar(&reportToSpec, "report-to", "", "Target sink as kind/namespace/name (kind is configmap|secret)")
	cmd.Flags().StringVar(&summaryPath, "summary-file", "", "Optional summary JSON path (uploaded under key summary.json)")
	cmd.Flags().DurationVar(&watchInterval, "watch-interval", 500*time.Millisecond, "Poll interval while waiting for the report file")
	cmd.Flags().DurationVar(&maxWaitTimeout, "max-wait", 0, "Maximum time to wait for the report file before uploading what exists (0 = wait until SIGTERM)")
	return cmd
}

type reportUploaderOptions struct {
	ReportFile     string
	SummaryFile    string
	ReportToSpec   string
	WatchInterval  time.Duration
	MaxWaitTimeout time.Duration
}

func runReportUploader(ctx context.Context, opts reportUploaderOptions) error {
	if opts.WatchInterval <= 0 {
		opts.WatchInterval = 500 * time.Millisecond
	}

	waitCtx := ctx
	if opts.MaxWaitTimeout > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, opts.MaxWaitTimeout)
		defer cancel()
	}

	if err := waitForFile(waitCtx, opts.ReportFile, opts.WatchInterval); err != nil {
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("wait for report file: %w", err)
		}
	}

	return uploadIfPresent(ctx, opts)
}

func waitForFile(ctx context.Context, path string, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func uploadIfPresent(ctx context.Context, opts reportUploaderOptions) error {
	raw, err := os.ReadFile(opts.ReportFile) // #nosec G304 -- path comes from a flag, intentional.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read report file: %w", err)
	}
	return uploadReport(ctx, opts.ReportToSpec, string(raw))
}
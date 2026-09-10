// Package main is the entry point for the CertAuth application.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/internal/sqlogger"
	"github.com/alastria/isbe-onboarding/mainserver"
)

var logLevel slog.Level = slog.LevelDebug

func main() {
	if err := run(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run() error {

	// Load configuration
	cfg, adminPassword, err := mainserver.LoadConfig()
	if err != nil {
		return errl.Errorf("failed to load configuration: %v", err)
	}

	// Initialize the custom SQLogHandler
	logOptions := &sqlogger.Options{
		Level:  &logLevel,
		LogDir: "data/logs",
	}

	// Check if the logs should be colored:
	// - If the process is running in a container (pid=1) then do not color the logs.
	// - Otherwise, if the environment variable CERTAUTH_LOGS_NOCOLOR is set to "true" then do not color the logs.
	ourpid := os.Getpid()
	if ourpid == 1 || mainserver.GetBoolEnvOrDefault("CERTAUTH_LOGS_NOCOLOR", false) {
		logOptions.NoColor = true
	}

	// Initialize the logging system
	sqlog, err := sqlogger.NewSQLogHandler(logOptions)
	if err != nil {
		return errl.Errorf("failed to initialize SQLogHandler: %v", err)
	}
	defer sqlog.Close()

	// And set the default logging system for all components
	slog.SetDefault(slog.New(sqlog))

	// Pretty-print the full config
	fmt.Println("Full config:")
	out, _ := json.MarshalIndent(cfg, "", "  ")
	fmt.Println(string(out))
	fmt.Println("Full config end")

	// Create the main server. This will initialize the individual HTTP services and the database.
	srv, err := mainserver.New(adminPassword, *cfg)
	if err != nil {
		return errl.Errorf("failed to create server: %v", err)
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		slog.Info("Shutdown signal received")
		cancel()
	}()

	// Start servers
	if err := srv.Start(ctx); err != nil {
		return errl.Errorf("server failed: %v", err)
	}

	return nil
}
